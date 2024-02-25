#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

/* コントロールブロックの状態を示す定数 */
#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

/* 送信元ポート番号の範囲 */
/* see https://tools.ietf.org/html/rfc6335 */
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

/* 疑似ヘッダ構造体(チェックサム計算時に使用する) */
struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

/* UDPヘッダ構造体 */
struct udp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

/* コントロールブロックの構造体 */
struct udp_pcb
{
    int state;
    struct ip_endpoint local; /* 自分のアドレス&ポート番号 */
    struct queue_head queue;  /* receive queue */
    int wc;                   /* waitカウント(PCBを使用中のスレッドの数) */
};

/* 受信キューのエントリの構造体 */
struct udp_queue_entry
{
    struct ip_endpoint foreign; /* 送信元のアドレス&ポート番号 */
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE]; /* コントロールブロックの配列 */

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static struct udp_pcb *
udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;

    /* 使用されていないPCBを探して返す */
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_FREE)
        {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
    }

    /* 空きがなければNULLを返す */
    return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_enty *entry;

    /* waitカウントが0でなかったら解放できないのでCLOSING状態にして抜ける */
    if (pcb->wc)
    {
        pcb->state = UDP_PCB_STATE_CLOSING;
        return;
    }

    /* 値をクリア */
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;

    /* 受信キューを空にする */
    while (1)
    {
        entry = queue_pop(&pcb->queue);
        if (!entry)
        {
            break;
        }
        memory_free(entry);
    }
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        /* OPEN状態のPCBのみが対象 */
        if (pcb->state == UDP_PCB_STATE_OPEN)
        {
            /* IPアドレスとポート番号が一致するPCBを探して返す */
            /* IPアドレスがワイルドカード(IP_ADDR_ANY)の場合、すべてのアドレスに対して一致の判定を下す */
            if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port)
            {
                return pcb;
            }
        }
    }

    /* 一致するものがなければNULLを返す */
    return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    /* 配列の範囲チェック(idをそのまま配列のインデックスとして使う) */
    if (id < 0 || id >= (int)countof(pcbs))
    {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    /* OPEN状態でなければNULLを返す */
    if (pcb->state != UDP_PCB_STATE_OPEN)
    {
        return NULL;
    }
    return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
    /* 配列のインデックスをidとして返す */
    return indexof(pcbs, pcb);
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

    /* ヘッダサイズに満たないデータはエラーとする */
    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }

    /* IPから渡されたデータ長(len)とUDPヘッダに含まれるデータグラム長(hdr->len)が一致しない場合はエラー */
    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len))
    {
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }

    /* チェックサム計算のために疑似ヘッダを準備 */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);

    /* 疑似ヘッダ部分のチェックサムを計算(計算結果はビット反転されているので戻しておく) */
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);

    /* UDPデータグラム部分のチェックサムを計算(cksum16()の第三引数にpsumを渡すことで続きを計算できる) */
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    udp_dump(data, len);

    /* PCBへのアクセスをmutexで保護 */
    mutex_lock(&mutex);

    /* 宛先アドレスとポート番号に対応するPCBを検索 */
    pcb = udp_pcb_select(dst, hdr->dst);

    /* PCBが見つからなければ中断(ポートを使用しているアプリケーションが存在しない) */
    if (!pcb)
    {
        /* port is not in use */
        mutex_unlock(&mutex); /* PCBへのアクセスが終わったらmutexのunlockを行う */
        return;
    }

    /* 受信キューのエントリのメモリを確保 */
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        mutex_unlock(&mutex); /* PCBへのアクセスが終わったらmutexのunlockを行う */
        errorf("memory_alloc() failure");
        return;
    }

    /* エントリの各項目へ値を設定する */
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry->data, hdr + 1, entry->len);

    /* PCBの受信キューにエントリをプッシュ */
    if (!queue_push(&pcb->queue, entry))
    {
        mutex_unlock(&mutex); /* PCBへのアクセスが終わったらmutexのunlockを行う */
        errorf("queue_push() failure");
        return;
    }

    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
    mutex_unlock(&mutex); /* PCBへのアクセスが終わったらmutexのunlockを行う */
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* IPのペイロードに載せ切れないほど大きなデータが渡されたらエラーを返す */
    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr))
    {
        errorf("too long");
        return -1;
    }

    /* UDPデータグラムの生成 */
    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    total = sizeof(*hdr) + len;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len); /* UDPのデータ部 */

    /* 疑似ヘッダの生成 */
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);

    /* 疑似ヘッダを含めたチェックサムの計算を行い、UDPヘッダに設定する */
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);

    /* IPの送信関数の呼び出し */
    if (ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1)
    {
        errorf("ip_output() failure");
        return -1;
    }

    return len;
}

static void
event_handler(void *arg)
{
}

int udp_init(void)
{
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}

/*
 * UDP User Commands
 */

int udp_open(void)
{
    struct udp_pcb *pcb;
    int id;

    /* PCBへのアクセスをmutexで保護 */
    mutex_lock(&mutex);

    /* 新しくPCBを割り当てる */
    pcb = udp_pcb_alloc();
    if (!pcb)
    {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex); /* PCBへのアクセスが終わったのでmutexをunlock */
        return -1;
    }

    /* 新しく割り当てたPCBのidを取得する */
    id = udp_pcb_id(pcb);
    mutex_unlock(&mutex); /* PCBへのアクセスが終わったのでmutexをunlock */

    /* 新しく割り当てたPCBのidを返す */
    return id;
}

int udp_close(int id)
{
    struct udp_pcb *pcb;

    /* PCBへのアクセスをmutexで保護 */
    mutex_lock(&mutex);

    /* IDからPCBのポインタを取得 */
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%s", id);
        mutex_unlock(&mutex); /* PCBへのアクセスが終わったのでmutexをunlock */
        return -1;
    }

    /* PCBを解放*/
    udp_pcb_release(pcb);
    mutex_unlock(&mutex); /* PCBへのアクセスが終わったのでmutexをunlock */

    return 0;
}

int udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);

    /* IDからPCBのポインタを取得 */
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%s", id);
        mutex_unlock(&mutex);
        return -1;
    }

    /* すでに使用されているアドレスとポートの組み合わせになっていないかを確認する */
    exist = udp_pcb_select(local->addr, local->port);
    if (exist)
    {
        errorf("already in use, id=%d, want=%s, exist=%s",
               id, ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }

    /* PCBにlocalの値をコピー */
    pcb->local = *local;

    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex); /* PCBへのアクセスをmutexで保護 */

    /* IDからPCBのポインタを取得 */
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    local.addr = pcb->local.addr;

    /* 自分の使うアドレスがワイルドカードだったら宛先アドレスに応じて送信元アドレスを自動的に選択する */
    if (local.addr == IP_ADDR_ANY)
    {
        /* IPの経路情報から宛先に到達可能なインタフェースを取得 */
        iface = ip_route_get_iface(foreign->addr);
        if (!iface)
        {
            errorf("iface not found that can reach foreign address, addr=%s",
                   ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->unicast; /* 取得したインタフェースのアドレスを使う */
        debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
    }

    /* 自分の使うポート番号が設定されていなかったら送信元ポートを自動的に選択する */
    if (!pcb->local.port)
    {
        /* 送信元ポート番号の範囲から使用可能なポートを探してPCBに割り当てる(使用されてないポートを探す) */
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++)
        {
            if (!udp_pcb_select(local.addr, hton16(p)))
            {
                pcb->local.port = hton16(p); /* このPCBで使用するポートに設定する */
                debugf("dynamic assign local port, port=%d", p);
                break;
            }
        }

        /* 使用可能なポートがなかったらエラーを返す */
        if (!pcb->local.port)
        {
            debugf("failed to dynamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
    }

    local.port = pcb->local.port;
    mutex_unlock(&mutex);
    return udp_output(&local, foreign, data, len);
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ssize_t len;

    mutex_lock(&mutex); /* PCBへのアクセスをmutexで保護 */

    /* IDからPCBのポインタを取得 */
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }

    while (1)
    {
        /* 受信キューからエントリを取り出す*/
        entry = queue_pop(&pcb->queue);
        if (entry)
        {
            break; /* エントリを取り出せたらループから抜ける */
        }

        /* waitカウントをインクリメント */
        pcb->wc++;

        /* 受信キューにエントリが追加されるのを待つ(1秒おきにキューを確認) */
        mutex_unlock(&mutex);
        sleep(1);

        /* waitカウントをデクリメント */
        mutex_lock(&mutex);
        pcb->wc--;

        /* PCBがCLOSING状態になっていたらPCBを解放してエラーを返す */
        if (pcb->state == UDP_PCB_STATE_CLOSING)
        {
            debugf("closed");
            udp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }

    mutex_unlock(&mutex);

    /* 送信元のアドレス&ポート番号をコピー */
    if (foreign)
    {
        *foreign = entry->foreign;
    }

    /* バッファが小さかったら切り詰めて格納する */
    len = MIN(size, entry->len);
    memcpy(buf, entry->data, len);

    /* 受信キューから取り出したエントリはもう使用しないのでメモリを解放する */
    memory_free(entry);

    /* バッファにコピーしたバイト数を返す */
    return len;
}
