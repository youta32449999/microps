#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "platform.h"

#include "util.h"

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

static pthread_t tid;
static pthread_barrier_t barrier;

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
}

static void *
intr_thread(void *arg)
{
}

int intr_run(void)
{
}

void intr_shutdown(void)
{
}

int intr_init(void)
{
}
