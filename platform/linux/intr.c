#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "platform.h"

#include "util.h"
#include "net.h"

/* 割り込み要求(IRQ)の構造体 */
struct irq_entry
{
    struct irq_entry *next;                      /* 次のIRQ構造体へのポインタ */
    unsigned int irq;                            /* 割り込み番号(IRQ番号) */
    int (*handler)(unsigned int irq, void *dev); /* 割り込みハンドラ(割り込みが発生した際に呼び出す関数へのポインタ) */
    int flags;                                   /* フラグ(INTR_IRQ_SHAREDが指定された場合はIRQ番号を共有可能) */
    char name[16];                               /* デバッグ出力で識別するための名前 */
    void *dev;                                   /* 割り込みの発生元となるデバイス(struct net_device以外にも対応できるようにvoid*で保持) */
};

/* NOTE: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex. */
static struct irq_entry *irqs; /* IRQリスト(リストの先頭を指すポインタ) */

static sigset_t sigmask; /* シグナル集合(シグナルマスク用) */

static pthread_t tid;             /* 割り込みスレッドのスレッドID */
static pthread_barrier_t barrier; /* スレッド間同期のためのバリア */

int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next)
    {
        if (entry->irq == irq)
        {
            /* IRQ番号が既に登録されている場合、IRQ番号の共有が許可されているかどうかをチェック
               どちらかが共有を許可してない場合はエラーを返す */
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED)
            {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }

    /* IRQリストへ新しいエントリを追加 */
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;

    /* IRQリストの先頭へ挿入 */
    entry->next = irqs;
    irqs = entry;

    /* シグナル集合へ新しいシグナルを追加 */
    sigaddset(&sigmask, irq);

    debugf("registered: irq=%u, name=%s", irq, name);

    return 0;
}

int intr_raise_irq(unsigned int irq)
{
    /* 割り込み処理スレッドへシグナルを送信 */
    return pthread_kill(tid, (int)irq);
}

/* 割り込みスレッドのエントリポイント */
static void *
intr_thread(void *arg)
{
    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");

    /* メインスレッドと同期を取るための処理 */
    pthread_barrier_wait(&barrier);
    while (!terminate)
    {
        /* 割り込みに見立てたシグナルが発生するまで待機 */
        err = sigwait(&sigmask, &sig);
        if (err)
        {
            errorf("sigwait() %s", strerror(err));
            break;
        }

        /* 発生したシグナルの種類に応じた処理を記述 */
        switch (sig)
        {
        /* 割り込みスレッドへ終了を通知するためのシグナル */
        case SIGHUP:
            terminate = 1;
            break;
        /* ソフトウェア割り込み用のシグナル */
        case SIGUSR1:
            net_softirq_handler();
            break;
        /* デバイス割り込み用のシグナル */
        default:
            /* IRQリストを巡回 */
            for (entry = irqs; entry; entry = entry->next)
            {
                /* IRQ番号が一致するエントリの割り込みハンドラを呼び出す */
                if (entry->irq == (unsigned int)sig)
                {
                    debugf("irq=%d, name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
            break;
        }
    }

    debugf("terminated");
    return NULL;
}

int intr_run(void)
{
    int err;

    /* シグナルマスクの設定 */
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err)
    {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }

    /* 割り込み処理スレッドの起動 */
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err)
    {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }

    /* スレッドが動き出すまで待つ
       (他のスレッドが同じようにpthread_barrier_wait()を呼び出し、
       バリアのカウントが指定の数になるまでスレッドを停止する) */
    pthread_barrier_wait(&barrier);

    return 0;
}

void intr_shutdown(void)
{
    /* 割り込み処理スレッドが起動済みかどうか確認 */
    if (pthread_equal(tid, pthread_self()) != 0)
    {
        /* Thread not created. */
        return;
    }

    /* 割り込み処理スレッドにシグナル(SIGHUP)を送信 */
    pthread_kill(tid, SIGHUP);

    /* 割り込み処理スレッドが完全に終了するのを待つ */
    pthread_join(tid, NULL);
}

int intr_init(void)
{
    /* スレッドIDの初期値にメインスレッドのIDを設定する */
    tid = pthread_self();

    /* pthread_barrierの初期化(カウントを2に設定) */
    pthread_barrier_init(&barrier, NULL, 2);

    /* シグナル集合を初期化(空にする) */
    sigemptyset(&sigmask);

    /* シグナル集合にSIGHUPを追加(割り込みスレッド終了通知用) */
    sigaddset(&sigmask, SIGHUP);
    /* シグナル集合にSIGUSR1を追加(ソフトウェア割り込み用) */
    sigaddset(&sigmask, SIGUSR1);

    return 0;
}
