#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal); /* シグナルハンドラの設定(Ctrl+Cが押された時にお行儀よく終了するように) */

    /* プロトコルスタックの初期化 */
    if (net_init() == -1)
    {
        errorf("net_init() failure");
        return -1;
    }

    /* ダミーデバイスの初期化(デバイスドライバがプロトコルスタックへの登録まで済ませる) */
    dev = loopback_init();
    if (!dev)
    {
        errorf("loopback_init() failure");
        return -1;
    }

    /* IPアドレスとサブネットマスクを指定してIPインタフェースを生成 */
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    /* IPインタフェースの登録(devにifaceが紐づけられる) */
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }

    /* Ethernetデバイスの生成 */
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev)
    {
        errorf("ether_tap_init() failure");
        return -1;
    }

    /* IPインタフェースを生成して紐づける */
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }

    /* デフォルトゲートウェイを登録(192.0.2.1) */
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1)
    {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }

    /* プロトコルスタックの起動 */
    if (net_run() == -1)
    {
        errorf("net_run() failure");
        return -1;
    }

    return 0;
}

static void
cleanup(void)
{
    /* プロトコルスタックの停止 */
    net_shutdown();
}

int main(int argc, char *argv[])
{
    int soc;
    struct ip_endpoint local;

    if (setup() == -1)
    {
        errorf("setup() failure");
        return -1;
    }

    /* UDPソケットをオープン */
    soc = udp_open();
    if (soc == -1)
    {
        errorf("udp_open() failure");
        return -1;
    }

    /* 0.0.0.0(ワイルドカードアドレス)を指定すると利用可能なすべてのアドレスが対象となる */
    ip_endpoint_pton("0.0.0.0:7", &local);

    /* ソケットにアドレスとポート番号を紐付け */
    if (udp_bind(soc, &local) == -1)
    {
        errorf("udp_bind() failure");
        udp_close(soc);
        return -1;
    }

    debugf("waiting for data...");
    while (!terminate)
    {
        sleep(1); /* このステップでは何もせず待ち続ける */
    }
    udp_close(soc);
    cleanup();
    return 0;
}
