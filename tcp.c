#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "tcp.h"

/* TCPヘッダのフラグフィールドの値 */
#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

#define TCP_DEFAULT_RTO 200000     /* micro seconds */
#define TCP_RETRANSMIT_DEADLINE 12 /* seconds */

/* 疑似ヘッダ構造体(チェックサム計算時に使用する) */
struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

/* TCPヘッダ構造体 */
struct tcp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

struct tcp_segment_info
{
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

/* コントロールブロックの構造体 */
struct tcp_pcb
{
    /* コネクションの状態 */
    int state;
    /* コネクションの両端のアドレス情報 */
    struct ip_endpoint local;
    struct ip_endpoint foreign;
    /* 送信時に必要になる情報 */
    struct
    {
        uint32_t nxt;
        uint32_t una;
        uint16_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss;
    /* 受信時に必要になる情報 */
    struct
    {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    uint8_t buf[65535]; /* receive buffer */
    struct sched_ctx ctx;
    struct queue_head queue; /* retransmit queue */
};

/* 再送キュー */
struct tcp_queue_entry
{
    struct timeval first; /* 初回送信時刻 */
    struct timeval last;  /* 最終送信時刻(前回の送信時刻) */
    unsigned int rto;     /* micor seconds. 再送タイムアウト(前回の再送時刻からこの時間が経過したら再送を実施) */
    uint32_t seq;         /* セグメントのシーケンス番号 */
    uint8_t flg;          /* セグメントの制御フラグ */
    size_t len;           /* entryのdataメンバのバイト数 */
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

static char *
tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

static void
tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * TCP Protocol Control Block (PCB)
 *
 * NOTE: TCP PCB functions must be called after mutex locked
 */

static struct tcp_pcb *
tcp_pcb_alloc(void)
{
    struct tcp_pcb *pcb;

    /* FREE状態のPCBを見つけて、CLOSED状態に初期化して返す */
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == TCP_PCB_STATE_FREE)
        {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* PCBを利用しているタスクがいたらこのタイミングでは解放できない */
    if (sched_ctx_destroy(&pcb->ctx) == -1)
    {
        /* タスクを起床させて他のタスクに解放を任せる */
        sched_wakeup(&pcb->ctx);
        return;
    }

    debugf("released, local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb)); /* pcbp->state is set to TCP_PCB_STATE_FREE (= 0) */
}

static struct tcp_pcb *
tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port)
        {
            /* ローカルアドレスにbind可能かどうかを調べるときは外部アドレスを指定せずに呼ばれる */
            if (!foreign)
            {
                return pcb;
            }

            /* ローカルアドレスと外部アドレスが共にマッチ */
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port)
            {
                return pcb;
            }

            /* 外部アドレスを指定せずにLISTENしていたらどんな外部アドレスでもマッチする */
            if (pcb->state == TCP_PCB_STATE_LISTEN)
            {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0)
                {
                    /* ローカルアドレス/外部アドレス共にマッチしたものが優先されるのですぐには返さない */
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

static struct tcp_pcb *
tcp_pcb_get(int id)
{
    struct tcp_pcb *pcb;

    /* idが有効な範囲かの検証 */
    if (id < 0 || id >= (int)countof(pcbs))
    {
        return NULL;
    }

    pcb = &pcbs[id];
    /* 使用されてないPCBの場合は初期化処理されていない状態なので返却しない */
    if (pcb->state == TCP_PCB_STATE_FREE)
    {
        return NULL;
    }
    return pcb;
}

static int
tcp_pcb_id(struct tcp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

static ssize_t
tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* TCPセグメントの生成 */
    hdr = (struct tcp_hdr *)buf;
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4; /* TCPヘッダの長さ(32ビット単位なのでsizeofで求まる1バイト単位の長さを1/4にする必要がある)。DataOffsetは4bitなので左に4bit詰める必要がある */
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len); /* TCPセグメントのデータ部 */

    /* 疑似ヘッダの生成 */
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);

    /* 疑似ヘッダを含めたチェックサムの計算を行い、TCPヘッダに設定する */
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
           total, len);
    tcp_dump((uint8_t *)hdr, total);

    /* IPの送信関数を呼び出す */
    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1)
    {
        errorf("ip_output() failure");
        return -1;
    }

    return len;
}

/**
 * TCP Retransmit
 *
 * NOTE: TCP Retransmit functions must be called after mutex locked
 */

static int
tcp_retransmit_queue_add(struct tcp_pcb *pcb, uint32_t seq, uint8_t flg, uint8_t *data, size_t len)
{
    struct tcp_queue_entry *entry;

    /* エントリのメモリを確保 */
    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }

    /* 再送タイムアウトにデフォルト値を設定 */
    entry->rto = TCP_DEFAULT_RTO;

    /* セグメントのシーケンス番号と制御フラグをコピー */
    entry->seq = seq;
    entry->flg = flg;

    /* TCPセグメントのデータ部分をコピー(制御フラグのみでデータがない場合は0バイトのコピー) */
    entry->len = len;
    memcpy(entry->data, data, entry->len);

    /* 最終送信時刻にも同じ値を入れておく(0回目の再送時刻) */
    gettimeofday(&entry->first, NULL);
    entry->last = entry->first;

    /* 再送キューにエントリを格納 */
    if (!queue_push(&pcb->queue, entry))
    {
        errorf("queue_push() failure");
        memory_free(entry);
        return -1;
    }

    return 0;
}

static void
tcp_retransmit_queue_cleanup(struct tcp_pcb *pcb)
{
    struct tcp_queue_entry *entry;

    while (1)
    {
        /* 受信キューの先頭のエントリを覗き見る */
        entry = queue_peek(&pcb->queue);
        if (!entry)
        {
            break;
        }

        /* ACKの応答が得られてなかったら処理を抜ける */
        if (entry->seq >= pcb->snd.una)
        {
            break;
        }

        /* ACKの応答が得られていたら受信キューから取り出す */
        entry = queue_pop(&pcb->queue);
        debugf("remove, seq=%u, flags=%s, len=%u", entry->seq, tcp_flg_ntoa(entry->flg), entry->len);

        /* エントリのメモリを削除する */
        memory_free(entry);
    }
    return;
}

static void
tcp_retransmit_queue_emit(void *arg, void *data) /* TCPタイマの処理から定期的に呼び出される */
{
    struct tcp_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval now, diff, timeout;

    pcb = (struct tcp_pcb *)arg;
    entry = (struct tcp_queue_entry *)data;

    /* 初回送信からの経過時間を計算 */
    gettimeofday(&now, NULL);
    timersub(&now, &entry->first, &diff);

    /* 初回送信からの経過時間がデッドラインを超えていたらコネクションを破棄する */
    if (diff.tv_sec >= TCP_RETRANSMIT_DEADLINE)
    {
        pcb->state = TCP_PCB_STATE_CLOSED;
        sched_wakeup(&pcb->ctx);
        return;
    }

    /* 再送予定時刻を計算 */
    timeout = entry->last;
    timeval_add_usec(&timeout, entry->rto);

    /* 再送予定時刻を過ぎていたらTCPセグメントを再送する */
    if (timercmp(&now, &timeout, >))
    {
        tcp_output_segment(entry->seq, pcb->rcv.nxt, entry->flg, pcb->rcv.wnd, entry->data, entry->len, &pcb->local, &pcb->foreign);
        entry->last = now; /* 最終送信時刻を更新 */
        entry->rto *= 2;   /* 再送タイムタウト(次の再送までの時間)を2倍の値で設定 */
    }
}

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;

    seq = pcb->snd.nxt;
    /* SYNフラグが指定されるのは初回送信時なのでiss(初期送信シーケンス番号)を使う */
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN))
    {
        seq = pcb->iss;
    }

    /* シーケンス番号を消費するセグメントだけ再送キューへ格納する(単純なACKセグメントやRSTセグメントは対象外) */
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len)
    {
        tcp_retransmit_queue_add(pcb, seq, flg, data, len);
    }

    /* PCBの情報を使ってTCPセグメントを送信 */
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;
    int acceptable = 0;

    pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED)
    {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
        {
            return;
        }

        /* 使用してないポートに何か飛んできたらRSTを返す */
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
        {
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        }
        else
        {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }

    switch (pcb->state)
    {
    case TCP_PCB_STATE_LISTEN:
        /*
         * 1st check for an RST
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) /* RSTフラグを含むセグメントは無視 */
        {
            return;
        }

        /*
         * 2nd check for an ACK
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) /* ACKフラグを含んでいたらRSTを送信 */
        {
            /* 相手が次に期待しているシーケンス番号(seg->ack)を設定 */
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }

        /*
         * 3rd check for an SYN
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN))
        {
            /* ignore: security/compartment check */
            /* ignore: precedence check */

            /* 両端の具体的なアドレスが確定する */
            pcb->local = *local;
            pcb->foreign = *foreign;

            pcb->rcv.wnd = sizeof(pcb->buf);                     /* 受信ウィンドウのサイズを設定 */
            pcb->rcv.nxt = seg->seq + 1;                         /* 次に受信を期待するシーケンス番号(ACKで使われる) */
            pcb->irs = seg->seq;                                 /* 初期受信シーケンス番号の保存 */
            pcb->iss = random();                                 /* 初期受信シーケンス番号の採番 */
            tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0); /* SYN+ACKの送信 */
            pcb->snd.nxt = pcb->iss + 1;                         /* 次に送信するシーケンス番号 */
            pcb->snd.una = pcb->iss;                             /* ACKが返ってきてない最後のシーケンス番号 */
            pcb->state = TCP_PCB_STATE_SYN_RECEIVED;             /* SYN_RECEIVEDへ移行 */

            /* ignore: Note that any other incoming control or data */
            /* (combined with SYN) will be processed in the SYN-RECEIVED state. */
            /* but processing of SYN and ACK should not be repeated */

            return;
        }

        /*
         * 4th other text or control
         */

        /* drop segment */
        return;
    case TCP_PCB_STATE_SYN_SENT:
        /*
         * 1st check the ACK bit
         */

        /*
         * 2nd check the RST bit
         */

        /*
         * 3rd check security and precedence (ignore)
         */

        /*
         * 4th check the SYN bit
         */

        /*
         * 5th, if neither of the SYN or RST bits is set then drop the segment and return
         */

        /* drop segment */
        return;
    }
    /*
     * Otherwise
     */

    /*
     * 1st check sequence number
     */
    switch (pcb->state)
    {
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
        /* 受信セグメントにデータが含まれているかどうか */
        if (!seg->len)
        {
            /* 受信バッファに空きがあるかどうか */
            if (!pcb->rcv.wnd)
            {
                /* 次に期待しているシーケンス番号と一致するかどうか */
                if (seg->seq == pcb->rcv.nxt)
                {
                    acceptable = 1;
                }
            }
            else
            {
                /* 次に期待するシーケンス番号以上で、ウィンドウの範囲内なら受け入れる */
                if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd)
                {
                    acceptable = 1;
                }
            }
        }
        else
        {
            /* 受信バッファに空きがあるかどうか */
            if (!pcb->rcv.wnd)
            {
                /* not acceptable */
            }
            else
            {
                /*
                 * 次に期待するシーケンス番号以上でデータの開始位置がウィンドウの範囲内なら受け入れる
                 * もしくは受信済みと新しいデータの両方を含むセグメントで新しいデータがウィンドウの範囲内なら受け入れる
                 */
                if ((pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                    (pcb->rcv.nxt <= seg->seq + seg->len - 1 && seg->seq + seg->len - 1 < pcb->rcv.nxt + pcb->rcv.wnd))
                {
                    acceptable = 1;
                }
            }
        }

        if (!acceptable)
        {
            if (!TCP_FLG_ISSET(flags, TCP_FLG_RST))
            {
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            }
            return;
        }
        /*
         * In the following it is assumed that the segment is the idealized
         * segment that begins at RCV.NXT and does not exceed the window.
         * One could tailor actual segments to fit this assumption by
         * trimming off any portions that lie outside the window (including
         * SYN and FIN), and only processing further if the segment then
         * begins at RCV.NXT.  Segments with higher begining sequence
         * numbers may be held for later processing.
         */
    }

    /*
     * 2nd check the REST bit
     */

    /*
     * 3rd check security and precedenc (ignore)
     */

    /*
     * 4th check the SYN bit
     */

    /*
     * 5th check the ACK field
     */
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) /* ACKフラグを含んでいないセグメントは破棄 */
    {
        /* drop segment */
        return;
    }

    switch (pcb->state)
    {
    case TCP_PCB_STATE_SYN_RECEIVED:
        if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) /* 送信セグメントに対する妥当なACKかどうかの判断 */
        {
            pcb->state = TCP_PCB_STATE_ESTABLISHED; /* ESTABLISHEDの状態に移行(コネクション確立) */
            sched_wakeup(&pcb->ctx);                /* PCBの状態が変化するのを待っているスレッドを起床させる */
        }
        else
        {
            /* 相手が次に期待しているシーケンス番号(seg->ack)を設定して、RSTフラグを含んだセグメントを送信 */
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }

    /* fall through(ESTABLISHEDでの処理を継続) */
    case TCP_PCB_STATE_ESTABLISHED:
        /* まだACKを受け取っていない送信データに対するACKかどうか */
        if (pcb->snd.una < seg->ack && seg->ack <= pcb->snd.nxt) /* まだ確認が取れてないシーケンス番号が含まれるACKを受信した場合 */
        {
            /* 確認が取れているシーケンス番号の値を更新 */
            pcb->snd.una = seg->ack;
            tcp_retransmit_queue_cleanup(pcb);
            /* ignore: Users should receive positive acknowledgments for buffers
                        which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" response) */
            /* 最後にウィンドウの情報を更新した時よりも後に送信されたセグメントかどうか */
            if (pcb->snd.wl1 < seg->seq || (pcb->snd.wl1 == seg->seq && pcb->snd.wl2 <= seg->ack))
            {
                /* ウィンドウの情報を更新 */
                pcb->snd.wnd = seg->wnd;
                pcb->snd.wl1 = seg->seq;
                pcb->snd.wl2 = seg->ack;
            }
        }
        else if (seg->ack < pcb->snd.una) /* 既に確認済みの範囲に対するACK */
        {
            /* ignore */
        }
        else if (seg->ack > pcb->snd.nxt) /* 範囲外(まだ送信してないシーケンス番号)へのACK */
        {
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            return;
        }
        break;
    }

    /*
     * 6th check the URG bit (ignore)
     */

    /*
     * 7th process the segment text
     */
    switch (pcb->state)
    {
    case TCP_PCB_STATE_ESTABLISHED:
        if (len)
        {
            /* 受信データをバッファにコピーしてACKを返す */
            memcpy(pcb->buf + (sizeof(pcb->buf) - pcb->rcv.wnd), data, len);
            pcb->rcv.nxt = seg->seq + seg->len;    /* 次に期待するシーケンス番号を更新 */
            pcb->rcv.wnd -= len;                   /* データを格納した分だけウィンドウサイズを小さくする */
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0); /* 確認応答(ACK)を送信 */
            sched_wakeup(&pcb->ctx);               /* 休止中のタスクを起床させる */
        }
        break;
    }

    /*
     * 8th check the FIN bit
     */

    return;
}

static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;

    /* ヘッダサイズに満たないデータはエラーとする */
    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;

    /* チェックサム計算のために疑似ヘッダを準備 */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    /* 疑似ヘッダ部分のチェックサムを計算(計算結果はビット反転されているので戻しておく) */
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);

    /* TCPセグメント部分のチェックサムを計算(cksum16()の第三引数にpsumを渡すことで続きを計算できる) */
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    /*
     * 送信先または宛先どちらかのアドレスがブロードキャストアドレスだった場合にはエラーメッセージを出力して中断する
     * TCPヘッダに含まれている送信元(src)と宛先(dst)はポート番号なので注意
     */
    if (src == IP_ADDR_BROADCAST || src == iface->broadcast || dst == IP_ADDR_BROADCAST || dst == iface->broadcast)
    {
        errorf("only supports unicast, src=%s, dst=%s",
               ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)));
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    tcp_dump(data, len);

    /* struct ip_endpointの変数に入れ直す */
    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;

    /* tcp_segment_arrives()で必要な情報(SEG.XXX)を集める */
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN))
    {
        seg.len++; /* SYN flag consumes one sequence number */
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN))
    {
        seg.len++; /* FIN flag consumes one sequence number */
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);

    return;
}

static void
tcp_timer(void)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == TCP_PCB_STATE_FREE)
        {
            continue;
        }
        /* 受信キューのすべてのエントリに対してtcp_retransmit_queue_emit()を実行する */
        queue_foreach(&pcb->queue, tcp_retransmit_queue_emit, pcb);
    }
    mutex_unlock(&mutex);
}

static void
event_handler(void *arg)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state != TCP_PCB_STATE_FREE)
        {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int tcp_init(void)
{
    struct timeval interval = {0, 100000};

    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    net_event_subscribe(event_handler, NULL);
    if (net_timer_register(interval, tcp_timer) == -1)
    {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}

/*
 * TCP User Command (RFC793)
 */

int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
    struct tcp_pcb *pcb;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb)
    {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }

    if (active)
    {
        debugf("active open: local=%s, foreign=%s, connectiong...",
               ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(foreign, ep2, sizeof(ep2)));
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf);
        pcb->iss = random(); /* シーケンス番号の初期値を採番 */

        /* SYNセグメントを送信 */
        if (tcp_output(pcb, TCP_FLG_SYN, NULL, 0) == -1)
        {
            errorf("tcp_output() failre");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }

        pcb->snd.una = pcb->iss;             /* まだACKの確認が得られていないシーケンス番号として設定 */
        pcb->snd.nxt = pcb->iss + 1;         /* 次に送信すべきシーケンス番号を設定 */
        pcb->state = TCP_PCB_STATE_SYN_SENT; /* SYN-SENT状態へ移行 */
    }
    else
    {
        debugf("passive open: local=%s, waiting for connection...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));
        pcb->local = *local;
        /* RFC793の仕様だと外部アドレスを限定してLISTEN可能(ソケットAPIではできない) */
        if (foreign)
        {
            pcb->foreign = *foreign;
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    }

AGAIN:
    state = pcb->state;
    /* waiting for state changed */
    while (pcb->state == state) /* PCBの状態が変化したらループを抜ける */
    {
        /* タスクを休止 */
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
        {
            /* シグナルによる割り込みが発生(EINTR) */
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }

    /* コネクション確立状態(ESTABLISHED)かどうかの確認 */
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED)
    {
        /* SYN_RECEIVEDの状態だったらリトライ */
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED)
        {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        /* PCBをCLOSED状態にしてリリース */
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }

    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    mutex_unlock(&mutex);

    /* コネクションが確立したらPCBのIDを返す */
    return id;
}

int tcp_close(int id)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    /* 暫定措置としてRSTを送信してコネクションを破棄 */
    tcp_output(pcb, TCP_FLG_RST, NULL, 0);
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

ssize_t
tcp_send(int id, uint8_t *data, size_t len)
{
    struct tcp_pcb *pcb;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state)
    {
    case TCP_PCB_STATE_ESTABLISHED:
        /* 送信に使われるインタフェースを取得 */
        iface = ip_route_get_iface(pcb->foreign.addr);
        if (!iface)
        {
            errorf("iface not found");
            mutex_unlock(&mutex);
            return -1;
        }
        /* MSS(Max Segment Size)を計算 */
        mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));

        /* 全て送信し切るまでループ処理 */
        while (sent < (ssize_t)len)
        {
            /* 相手の受信バッファの状況を予測 */
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);

            /* 相手の受信バッファが埋まっていたら空くまで待つ */
            if (!cap)
            {
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
                {
                    debugf("interrupted");
                    /* まだ何も送信してない状態でユーザ割り込みにより処理を中断 */
                    if (!sent)
                    {
                        mutex_unlock(&mutex);
                        errno = EINTR;
                        return -1;
                    }

                    /* 1バイトでも送信済みの場合(戻り値で送信済みのバイト数を返す必要がある) */
                    break;
                }
                /* 状態が変わっている可能性もあるので状態の確認から再試行 */
                goto RETRY;
            }

            /* MSSのサイズで分割して送信 */
            slen = MIN(MIN(mss, len - sent), cap);

            /* ACKフラグを含める。PSHフラグは飾り程度の扱い */
            if (tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen) == -1)
            {
                errorf("tcp_output() failure");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
                mutex_unlock(&mutex);
                return -1;
            }

            /* 次に送信するシーケンス番号を更新 */
            pcb->snd.nxt += slen;

            /* 送信済みバイト数を更新 */
            sent += slen;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }

    mutex_unlock(&mutex);

    /* 送信済みバイト数を返す */
    return sent;
}

ssize_t
tcp_receive(int id, uint8_t *buf, size_t size)
{
    struct tcp_pcb *pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state)
    {
    case TCP_PCB_STATE_ESTABLISHED:
        remain = sizeof(pcb->buf) - pcb->rcv.wnd;
        /* 受信バッファにデータが存在しない場合はタスクを休止 */
        if (!remain)
        {
            if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
            {
                /* まだ何も受信してない状態でユーザ割り込みにより処理を中断 */
                debugf("interrupted");
                mutex_unlock(&mutex);
                errno = EINTR;
                return -1;
            }
            /* 状態が変わっている可能性もあるため状態確認から再試行 */
            goto RETRY;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }

    /* bufに収まる分だけコピー */
    len = MIN(size, remain);
    memcpy(buf, pcb->buf, len);

    /* コピー済みのデータを受信バッファから削除 */
    memmove(pcb->buf, pcb->buf + len, remain - len);
    pcb->rcv.wnd += len;

    mutex_unlock(&mutex);

    /* 受信したバイト数を返す */
    return len;
}
