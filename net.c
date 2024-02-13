#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices; /* デバイスリスト(リストの先頭を指すポインタ) */

struct net_device *
net_device_alloc(void)
{
    struct net_device *dev;

    dev = memory_alloc(sizeof(*dev));
    if (!dev)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

/* NOTE: must not be call after net_run() */
int net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;

    dev->index = index++;                                        /* デバイスのインデックス番号を設定 */
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index); /* デバイス名を生成(net0, net1, net2, ...) */

    /* デバイスリストの先頭に追加 */
    dev->next = devices;
    devices = dev;

    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int
net_device_open(struct net_device *dev)
{
    /* デバイスの状態を確認(既にUP状態の場合はエラーを返す) */
    if (NET_DEVICE_IS_UP(dev))
    {
        errorf("already opend, dev=%s", dev->name);
        return -1;
    }

    /* デバイスドライバのオープン関数を呼び出す
       オープン関数が設定されてない場合は呼び出しをスキップ
       エラーが返されたらこの関数もエラーを返す */
    if (dev->ops->open)
    {
        if (dev->ops->open(dev) == -1)
        {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    /* UPフラグを立てる */
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev)
{
    /* デバイスの状態を確認(UPでない場合はエラーを返す) */
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    /* デバイスのクローズ関数を呼び出す
       クローズ関数が設定されてない場合は呼び出しをスキップ
       エラーが返されたらこの関数もエラーを返す */
    if (dev->ops->close)
    {
        if (dev->ops->close(dev) == -1)
        {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    /* UPフラグを落とす */
    dev->flags &= ~NET_DEVICE_FLAG_UP; /* ~は論理否定(各ビットを反転させる) */
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    /* デバイスの状態を確認(UP状態でなければ送信できないのでエラーを返す) */
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    /* データサイズを確認(デバイスのMTUを超えるサイズのデータは送信できないのでエラーを返す) */
    if (len > dev->mtu)
    {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    /* デバイスドライバの出力関数を呼び出す(エラーが返されたらこの関数もエラーを返す) */
    if (dev->ops->transmit(dev, type, data, len, dst) == -1)
    {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }

    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
}

int net_run(void)
{
}

void net_shutdown(void)
{
}

int net_init(void)
{
}
