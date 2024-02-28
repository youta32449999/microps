#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int sched_ctx_init(struct sched_ctx *ctx)
{
    /* 初期化 */
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

int sched_ctx_destroy(struct sched_ctx *ctx)
{
    /* 条件変数の破棄(待機中のスレッドが存在する場合にのみエラーが返る) */
    return pthread_cond_destroy(&ctx->cond);
}

int sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;

    /* interruptedのフラグが立っていたらerrnoにEINTRを設定してエラーを返す */
    if (ctx->interrupted)
    {
        errno = EINTR;
        return -1;
    }
    ctx->wc++; /* waitカウントをインクリメント */
    /*
     * pthread_cond_broadcast()が呼ばれるまでスレッドを休止させる
     * asbtimeが指定されていたら指定時刻に起床するpthread_cond_timedwait()を使用する
     * ※ 休止する際にはmutexがアンロックされ、起床する際にロックされた状態で戻ってくる
     */
    if (abstime)
    {
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
    }
    else
    {
        ret = pthread_cond_wait(&ctx->cond, mutex);
    }
    ctx->wc--; /* waitカウントをデクリメント */
    if (ctx->interrupted)
    {
        /* 休止中だったスレッドがすべて起床したらinterruptedフラグを下げる */
        if (!ctx->wc)
        {
            ctx->interrupted = 0;
        }

        /* errnoにEINTRを設定してエラーを返す */
        errno = EINTR;
        return -1;
    }
    return ret;
}

int sched_wakeup(struct sched_ctx *ctx)
{
    /* 休止しているスレッドを気象させる */
    return pthread_cond_broadcast(&ctx->cond);
}

int sched_interrupt(struct sched_ctx *ctx)
{
    /* interruptedフラグを立てた上で休止しているスレッドを起床させる */
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}
