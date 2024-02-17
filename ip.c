#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

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
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
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
