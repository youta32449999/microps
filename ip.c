#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

/**
 * IPヘッダを表現するための構造体
 * この構造体のポインタにキャストすることでバイト列をIPヘッダとみなしてアクセスできる
 */
struct ip_hdr
{
    uint8_t vhl; /* バージョン(4bit)とIPヘッダ長(4bit)をまとめて8bitとして扱う */
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset; /* フラグ(3bit)とフラグメントオフセット(13bit)をまとめて16bitとして扱う */
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[]; /* オプション(可変長なのでフレキシブル配列メンバとする) */
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces; /* 登録されているすべてのIPインタフェースのリスト */

/* IPアドレスを文字列からネットワークバイトオーダーのバイナリ値(ip_addr_t)に変換 */
int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++)
    {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
        {
            return -1;
        }
        if (ep == sp)
        {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
        {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

/* IPアドレスをネットワークバイトオーダーのバイナリ値(ip_addr_t)から文字列に変換 */
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4; /* vhlの上位4bit=バージョン */
    hl = hdr->vhl & 0x0f;       /* vhlの下位4bit=IPヘッダ長 */
    hlen = hl << 2;             /* IPヘッダ長は32bit(4byte)単位の値が格納されているので4倍して8bit(1byte)単位の値にする */
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);                                              /* 多バイト長(16bitや32bit)の数値データはバイトオーダーの変換が必要 */
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen); /* トータル長からIPヘッダ長を引いたものが運んでいるデータ(ペイロード)の長さ */
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff); /* offsetの上位3bit = フラグ, 下位13bit = フラグメントオフセット */
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr))); /* IPアドレスをネットワークバイトオーダーのバイナリ値(ip_addr_t)から文字列に変換 */
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    /* IPインタフェースのメモリを確保 */
    iface = memory_alloc(sizeof(*iface));
    if (!iface)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }

    /* インタフェースの種別を示すfamilyの値を設定 */
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    /* IPインタフェースにアドレス情報を設定*/
    if (ip_addr_pton(unicast, &iface->unicast) == -1)
    {
        errorf("ip_addr_pton() failure, addr=%s", unicast);
        memory_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1)
    {
        errorf("ip_addr_pton() failure, addr=%s", netmask);
        memory_free(iface);
        return NULL;
    }
    iface->broadcast = (iface->unicast & iface->netmask) | ~iface->netmask;

    return iface;
}

/* NOTE: must not be call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    /* IPインタフェースの登録 */
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1)
    {
        errorf("net_device_add_iface() failure");
        return -1;
    }

    /* IOインタフェースのリストの先頭にifaceを挿入する */
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s",
          dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr1)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

/* 引数addrで指定されたIPアドレスを持つインタフェースを返す */
struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    struct ip_iface *entry;

    for (entry = ifaces; entry; entry = entry->next)
    {
        if (entry->unicast == addr)
        {
            break;
        }
    }
    return entry;
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;

    /* 入力データの長さがIPヘッダの最小サイズより小さい場合はエラー */
    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }

    /* 入力データをIPヘッダ構造体のポインタへキャスト */
    hdr = (struct ip_hdr *)data;

    /* IPデータグラムの検証 */
    v = hdr->vhl >> 4;
    if (v != IP_VERSION_IPV4)
    {
        errorf("ip version error: v=%u", v);
        return;
    }
    hlen = (hdr->vhl & 0x0f) << 2;
    if (len < hlen)
    {
        errorf("header length error: len=%zu < hlen=%u", len, hlen);
        return;
    }
    total = ntoh16(hdr->total);
    if (len < total)
    {
        errorf("total length error: len=%zu < total=%u", len, total);
        return;
    }
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, hlen, -hdr->sum)));
        return;
    }

    /* 今回はIPのフラグメントをサポートしないのでフラグメントだったら処理せず中断する
       フラグメントかどうかの判断はMF(More Flagments)ビットが立っている or フラグメントオフセットに値がある */
    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff)
    {
        errorf("fragments does not support");
        return;
    }

    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total);
    ip_dump(data, total);
}

int ip_init(void)
{
    /* プロトコルスタックにIPの入力関数を登録する */
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1)
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}
