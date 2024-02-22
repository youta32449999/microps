#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001 /* ハードウェアアドレス種別(Ethernet) */
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP /* プロトコルアドレス種別(IP) */

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32

/* ARPキャッシュの状態を表す定数 */
#define ARP_CACHE_STATE_FREE 0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED 2
#define ARP_CACHE_STATE_STATIC 3

/* ARPヘッダの構造体 */
struct arp_hdr
{
    uint16_t hrd; /* ハードウェアアドレス種別 */
    uint16_t pro; /* プロトコルアドレス種別 */
    uint8_t hln;  /* ハードウェアアドレス長 */
    uint8_t pln;  /* プロトコルアドレス長 */
    uint16_t op;  /* オペレーションコード */
};

/**
 * Ethernet/IPペアのためのARPメッセージ構造体
 *
 * spa(tpa)をip_addr_tにするとsha(tha)とのあいだにパディングが挿入されてしまうので注意
 * アラインメント(境界揃え)処理によって32bit幅の変数は4の倍数のアドレスに配置するよう調整されてしまう
 */
struct arp_ether_ip
{
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN]; /* 送信元ハードウェアアドレス */
    uint8_t spa[IP_ADDR_LEN];    /* 送信元プロトコルアドレス */
    uint8_t tha[ETHER_ADDR_LEN]; /* ターゲット・ハードウェアアドレス */
    uint8_t tpa[IP_ADDR_LEN];    /* ターゲット・プロトコルアドレス */
};

/* ARPキャッシュの構造体 */
struct arp_cache
{
    unsigned char state;        /* キャッシュの状態 */
    ip_addr_t pa;               /* プロトコルアドレス */
    uint8_t ha[ETHER_ADDR_LEN]; /* ハードウェアアドレス */
    struct timeval timestamp;   /* 最終更新時刻 */
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE]; /* ARPキャッシュの配列(ARPテーブル) */

static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode))
    {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether_ip *)data; /* ここではEthernet/IPペアのメッセージとみなす */
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    /* ハードウェアアドレス(sha/tha): Ethernetアドレス(MACアドレス) */
    /* プロトコルアドレス(spa/tpa): IPアドレス */
    memcpy(&spa, message->spa, sizeof(spa)); /* spaがuint8_t[4]なので、一旦memcpy()でip_addr_tの変数へ取り出す */
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa)); /* tpaも同様にmemcpy()でip_addr_tの変数へ取り出す */
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * ARP Cache
 *
 * NOTE: ARP Cache functions must be called after mutex locked
 */

static void
arp_cache_delete(struct arp_cache *cache)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    /* キャッシュのエントリを削除する */
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

static struct arp_cache *
arp_cache_alloc(void)
{
    struct arp_cache *entry, *oldest = NULL;

    /* ARPキャッシュのテーブルを巡回 */
    for (entry = caches; entry < tailof(caches); entry++)
    {
        /* 使用されてないエントリを返す */
        if (entry->state == ARP_CACHE_STATE_FREE)
        {
            return entry;
        }

        /* 空きがなかったときのために一番古いエントリも一緒に探す */
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >))
        {
            oldest = entry;
        }
    }

    /* 現在登録されている内容を削除をする */
    arp_cache_delete(oldest);
    return oldest; /* 空きがなかったら一番古いエントリを返す */
}

static struct arp_cache *
arp_cache_select(ip_addr_t pa)
{
    struct arp_cache *entry;
    /*
     * キャッシュの中からプロトコルアドレスが一致するエントリを探して返す
     * 見つからなかったらNULLを返す。念のためFREE状態でないエントリの中から探す
     */
    for (entry = caches; entry < tailof(caches); entry++)
    {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa)
        {
            return entry;
        }
    }
    return NULL;
}

static struct arp_cache *
arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    /* IPアドレスに対応するエントリを取得する */
    cache = arp_cache_select(pa);
    if (!cache)
    {
        /* not found */
        return NULL;
    }

    /* キャッシュに登録されている情報を更新する */
    cache->state = ARP_CACHE_STATE_RESOLVED; /* IPアドレスに対応するMACアドレスが取得済みであることを表す */
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL); /* POSIX規格では第二引数にNULL以外の値を指定した時の挙動は未定義となっているため必ずNULLを指定する */

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));

    /* 更新後のエントリを返却する */
    return cache;
}

static struct arp_cache *
arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    /* キャッシュに新しく登録するエントリの登録スペースを確保する */
    cache = arp_cache_alloc();
    if (!cache)
    {
        errorf("arp_cache_alloc failure");
        return NULL;
    }

    /* エントリの情報を設定する */
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));

    /* 登録したエントリを返却する */
    return cache;
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;

    /* ARP応答メッセージの生成 */
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);

    /* インタフェースのIPアドレスと紐づくデバイスのMACアドレスを設定する */
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    /* unicastはip_addr_pton()によってネットワークバイトオーダーの32bit値として格納されているのでバイトオーダーの変換は不要 */
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);

    /* ARP要求を送ってきたノードのIPアドレスとMACアドレスを設定する */
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));

    /* デバイスからARPメッセージを送信 */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;

    /* 期待するARPメッセージのサイズより小さかったらエラーを返す */
    if (len < sizeof(*msg))
    {
        errorf("too short");
        return;
    }

    msg = (struct arp_ether_ip *)data;

    /* ハードウェアアドレスのチェック */
    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN)
    {
        errorf("unsupported hardware address");
        return;
    }

    /* プロトコルアドレスのチェック */
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN)
    {
        errorf("unsupported protocol address");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);

    /* spa/tpaをmemcpy()でip_addr_tの変数へ取り出す */
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    /* デバイスに紐づくIPインタフェースを取得する */
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);

    /* ARP要求のターゲットプロトコルアドレスと一致するか確認 */
    if (iface && ((struct ip_iface *)iface)->unicast == tpa)
    {
        /* ARP応答を受け取ることもあるので受け取ったARPパケットがARP要求であるかをチェックする必要がある */
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST)
        {
            /* ARP要求への応答 */
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
}

int arp_init(void)
{
    /* プロトコルスタックにARPの入力関数を登録する */
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1)
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}
