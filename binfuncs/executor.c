// executor_bin.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

// Must match compiler definitions exactly
typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    pthread_mutex_t lock;
} VarSlot;

typedef struct IRStmt {
    int lhs_index;
    void* func_ptr;
    int argc;
    int* arg_indices;
    int dead;
    int inlined;
    int dep_count;
    int* dep_indices;
    int executed;
} IRStmt;

// ----------------- Internal structures -----------------
typedef struct Dependents {
    int *list;
    int capacity;
    int count;
} Dependents;

typedef struct WorkQueue {
    int *buf;
    int capacity;
    int head;
    int tail;
    int size;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} WorkQueue;

typedef struct ExecContext {
    IRStmt* stmts;
    int stmt_count;
    VarSlot** env_array;
    int max_threads;
    atomic_int *dep_remaining;
    Dependents *dependents;
    WorkQueue queue;
    atomic_int remaining;
    long *args_buffer; // preallocated buffer for args
} ExecContext;

// ----------------- Queue helpers -----------------
static void queue_init(WorkQueue *q, int capacity){
    q->buf = malloc(sizeof(int) * capacity);
    if(!q->buf){ perror("malloc queue buf"); exit(EXIT_FAILURE); }
    q->capacity = capacity;
    q->head = q->tail = q->size = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_destroy(WorkQueue *q){
    if(q->buf) free(q->buf);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
    q->buf = NULL; q->capacity = q->head = q->tail = q->size = 0;
}

static void queue_push(WorkQueue *q, int val){
    pthread_mutex_lock(&q->mutex);
    q->buf[q->tail] = val;
    q->tail = (q->tail + 1) % q->capacity;
    q->size++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

static int queue_try_pop(WorkQueue *q, int *out){
    int got = 0;
    pthread_mutex_lock(&q->mutex);
    if(q->size > 0){
        *out = q->buf[q->head];
        q->head = (q->head + 1) % q->capacity;
        q->size--;
        got = 1;
    }
    pthread_mutex_unlock(&q->mutex);
    return got;
}

static int queue_pop_blocking(WorkQueue *q, int *out){
    pthread_mutex_lock(&q->mutex);
    while(q->size == 0){
        pthread_cond_wait(&q->cond, &q->mutex);
    }
    *out = q->buf[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->size--;
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

// ----------------- Executor -----------------
static void execute_single(IRStmt* s, VarSlot** env_array, long* args_buffer){
    if(s->dead || s->executed) return;

    if(s->inlined){
        long val = 0;
        for(int i=0;i<s->argc;i++){
            int ai = s->arg_indices[i];
            VarSlot* arg = env_array[ai];
            long aval = arg->constant ? arg->value : (long)arg->data;
            val += aval;
        }
        VarSlot* lhs = env_array[s->lhs_index];
        pthread_mutex_lock(&lhs->lock);
        lhs->value = val;
        lhs->constant = 0;
        pthread_mutex_unlock(&lhs->lock);
        s->executed = 1;
        return;
    }

    // preallocated args buffer
    for(int i=0;i<s->argc;i++){
        int ai = s->arg_indices[i];
        VarSlot* arg = env_array[ai];
        args_buffer[i] = arg->constant ? arg->value : (long)arg->data;
    }

    void (*fn)(long*, long*) = s->func_ptr;
    VarSlot* lhs = env_array[s->lhs_index];
    pthread_mutex_lock(&lhs->lock);
    fn(&lhs->value, args_buffer);
    lhs->constant = 0;
    pthread_mutex_unlock(&lhs->lock);

    s->executed = 1;
}

static void* worker_thread(void* vctx){
    ExecContext* ctx = (ExecContext*)vctx;
    int idx;
    while(atomic_load(&ctx->remaining) > 0){
        if(!queue_try_pop(&ctx->queue, &idx)){
            if(atomic_load(&ctx->remaining) <= 0) break;
            queue_pop_blocking(&ctx->queue, &idx);
        }
        IRStmt* s = &ctx->stmts[idx];
        if(s->dead && !s->executed){
            s->executed = 1;
            atomic_fetch_sub(&ctx->remaining, 1);
            continue;
        }
        execute_single(s, ctx->env_array, ctx->args_buffer + idx * 16); // 16 args max preallocated
        atomic_fetch_sub(&ctx->remaining, 1);

        Dependents *deps = &ctx->dependents[idx];
        for(int di = 0; di < deps->count; ++di){
            int d = deps->list[di];
            int prev = atomic_fetch_sub(&ctx->dep_remaining[d], 1);
            if(prev == 1) queue_push(&ctx->queue, d);
        }
    }
    return NULL;
}

static void build_dependents(ExecContext *ctx){
    int n = ctx->stmt_count;
    int *cnt = calloc(n, sizeof(int));
    if(!cnt){ perror("calloc cnt"); exit(EXIT_FAILURE); }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred >= 0 && pred < n) cnt[pred]++;
        }
    }

    ctx->dependents = malloc(sizeof(Dependents)*n);
    if(!ctx->dependents){ perror("malloc dependents"); exit(EXIT_FAILURE); }
    for(int i=0;i<n;i++){
        ctx->dependents[i].count = 0;
        ctx->dependents[i].capacity = cnt[i];
        ctx->dependents[i].list = cnt[i] > 0 ? malloc(sizeof(int)*cnt[i]) : NULL;
    }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred >= 0 && pred < n){
                ctx->dependents[pred].list[ctx->dependents[pred].count++] = i;
            }
        }
    }
    free(cnt);
}

static void free_dependents(ExecContext *ctx){
    if(!ctx->dependents) return;
    for(int i=0;i<ctx->stmt_count;i++) if(ctx->dependents[i].list) free(ctx->dependents[i].list);
    free(ctx->dependents);
    ctx->dependents = NULL;
}

// ----------------- Main exported function -----------------
void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads){
    if(!stmts || stmt_count <= 0) return;
    if(max_threads <= 0) max_threads = 1;

    ExecContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.stmts = stmts;
    ctx.stmt_count = stmt_count;
    ctx.env_array = env_array;
    ctx.max_threads = max_threads;

    ctx.dep_remaining = malloc(sizeof(atomic_int)*stmt_count);
    if(!ctx.dep_remaining){ perror("malloc dep_remaining"); exit(EXIT_FAILURE); }
    for(int i=0;i<stmt_count;i++) atomic_init(&ctx.dep_remaining[i], stmts[i].dep_count);

    build_dependents(&ctx);

    atomic_init(&ctx.remaining, 0);
    for(int i=0;i<stmt_count;i++){
        if(stmts[i].dead) stmts[i].executed = 1;
        else atomic_fetch_add(&ctx.remaining, 1);
    }

    queue_init(&ctx.queue, stmt_count + 8);

    // preallocate args buffer for all statements (16 args max per stmt)
    ctx.args_buffer = malloc(sizeof(long) * stmt_count * 16);
    if(!ctx.args_buffer){ perror("malloc args_buffer"); exit(EXIT_FAILURE); }

    for(int i=0;i<stmt_count;i++){
        if(stmts[i].dead) continue;
        if(atomic_load(&ctx.dep_remaining[i]) == 0) queue_push(&ctx.queue, i);
    }

    pthread_t *threads = malloc(sizeof(pthread_t)*max_threads);
    if(!threads){ perror("malloc threads"); exit(EXIT_FAILURE); }

    for(int t=0;t<max_threads;t++){
        pthread_create(&threads[t], NULL, worker_thread, &ctx);
    }
    for(int t=0;t<max_threads;t++){
        pthread_join(threads[t], NULL);
    }

    free(threads);
    free(ctx.args_buffer);
    queue_destroy(&ctx.queue);
    free_dependents(&ctx);
    free(ctx.dep_remaining);
}
