#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "ip.h"
#include "udp.h"

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

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

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
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
}

int udp_init(void)
{
}
