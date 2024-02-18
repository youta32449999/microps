#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/loopback.h"

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
    ip_addr_t src, dst;
    size_t offset = IP_HDR_SIZE_MIN; /* IPヘッダは自分で生成するのでIPヘッダの先を指すようにする */

    /* プロトコルスタックの初期化〜デバイスの登録〜起動までのセットアップ */
    if (setup() == -1)
    {
        errorf("setup() failure");
        return -1;
    }

    /* IPアドレスを文字列からネットワークバイトオーダーのバイナリ値へ変換 */
    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src; /* 宛先は送信元と同じIPアドレス */

    /* Ctrl+Cが押されるとシグナルハンドラon_signal()の中でterminateに1が設定される */
    while (!terminate)
    {
        /* 1秒おきにデバイスにパケットを書き込む */
        if (ip_output(IP_PROTOCOL_ICMP, test_data + offset, sizeof(test_data) - offset, src, dst) == -1)
        {
            errorf("ip_output() failure");
            break;
        }
        sleep(1);
    }

    cleanup();
    return 0;
}
