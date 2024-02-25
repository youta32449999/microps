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
}

int sched_wakeup(struct sched_ctx *ctx)
{
}

int sched_interrupt(struct sched_ctx *ctx)
{
}
