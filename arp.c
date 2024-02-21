#include <stdio.h>
#include <stdint.h>
#include <string.h>

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
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
}

int arp_init(void)
{
}
