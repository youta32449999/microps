#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define LOOPBACK_MTU UINT16_MAX /* maximum size of IP datagram */
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)

#define PRIV(x) ((struct loopback *)x->priv)

/* ループバックデバイスのドライバ内で使用するプライベートなデータを格納するための構造体 */
struct loopback
{
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

struct loopback_queue_entry
{
    uint16_t type;
    size_t len;
    uint8_t data[]; /* flexible array member */
};

static int
loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
}

static int
loopback_isr(unsigned int irq, void *id)
{
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

struct net_device *
loopback_init(void)
{
    struct net_device *dev;
    struct loopback *lo;

    /* デバイスの生成とパラメータの設定 */
    dev = net_device_alloc();
    if (!dev)
    {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops; /* デバイスドライバが実装している関数のアドレスを保持する構造体へのポインタを設定する */

    /* ドライバの中で使用するプライベートなデータの準備 */
    lo = memory_alloc(sizeof(*lo));
    if (!lo)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    lo->irq = LOOPBACK_IRQ;
    mutex_init(&lo->mutex);
    queue_init(&lo->queue);
    dev->priv = lo; /* プライベートなデータをデバイス構造体に格納する(ドライバの関数が呼び出される際にはデバイス構造体が渡されるのでここから取り出す) */

    /* デバイスの登録 */
    if (net_device_register(dev) == -1)
    {
        errorf("net_device_register() failure");
        return NULL;
    }
    /* 割り込みハンドラの登録 */
    intr_request_irq(lo->irq, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);

    debugf("initialized, dev=%s", dev->name);
    return dev;
}
