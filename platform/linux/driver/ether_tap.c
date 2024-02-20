#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE + 2)

struct ether_tap
{
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

#define PRIV(x) ((struct ether_tap *)x->priv)

static int
ether_tap_addr(struct net_device *dev)
{
    int soc;
    struct ifreq ifr = {}; /* ioctl()で使うリクエスト/レスポンス兼用の構造体 */

    /* ioctl()のSIOCGIFHWADDR要求がソケットとして開かれたディスクリプタでのみ有効なため、なんでもいいのでソケットをオープンする */
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1)
    {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    /* ハードウェアアドレスを取得したいデバイスの名前を設定する */
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);

    /* ハードウェアアドレスの取得を要求する */
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1)
    {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }

    /* 取得したアドレスをデバイス構造体へコピー */
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    /* 使い終わったソケットをクローズ */
    close(soc);

    return 0;
}

static int
ether_tap_open(struct net_device *dev)
{
    struct ether_tap *tap;
    struct ifreq ifr = {}; /* ioctlで使うリクエスト/レスポンス兼用の構造体 */

    tap = PRIV(dev);

    /* TUN/TAP制御用デバイスをオープン */
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1)
    {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    /* TAPデバイスの名前を設定 */
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1);

    /* フラグ設定(IFF_TAO: TAPモード、IFF_NO_PI: パケット情報ヘッダを付けない) */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    /* TAPデバイスの登録を要求 */
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1)
    {
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    /* シグナル駆動I/Oのための設定 */
    /* シグナルの配送先を設定 */
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1)
    {
        errorf("fcntl(FSETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    /* シグナル駆動I/Oを有効にする */
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1)
    {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    /* 送信するシグナルを指定 */
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1)
    {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    /* HWアドレスが明示的に設定されていなかったらOS側から見えているTAPデバイスのHWアドレスを取得して使用する */
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0)
    {
        if (ether_tap_addr(dev) == -1)
        {
            errorf("ether_tap_addr() failure, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }

    return 0;
}

static int
ether_tap_close(struct net_device *dev)
{
    close(PRIV(dev)->fd); /* ディスクリプタをクローズ */
    return 0;
}

static ssize_t
ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen) {}

int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
}

static ssize_t
ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{
}

static int
ether_tap_isr(unsigned int irq, void *id)
{
}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

struct net_device *
ether_tap_init(const char *name, const char *addr)
{
}
