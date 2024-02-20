#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ether.h"

/* Ethernetヘッダの構造体 */
struct ether_hdr
{
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

int ether_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n)
    {
        return -1;
    }

    for (index = 0; index < ETHER_ADDR_LEN; index++)
    {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':'))
        {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }

    if (index != ETHER_ADDR_LEN || *ep != '\0')
    {
        return -1;
    }

    return 0;
}

char *
ether_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p)
    {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

static void
ether_dump(const uint8_t *frame, size_t flen)
{
    struct ether_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    flockfile(stderr);
    fprintf(stderr, "        src: %s\n", ether_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ether_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "       type: 0x%04x\n", ntoh16(hdr->type));
#ifdef HEXDUMP
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}

int ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ether_transmit_func_t callback)
{
}

int ether_input_helper(struct net_device *dev, ether_input_func_t callback)
{
}

void ether_setup_helper(struct net_device *dev)
{
}
