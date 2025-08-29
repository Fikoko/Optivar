// executor.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

// Must match compiler's definitions exactly
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
    int* dep_indices; // predecessors
    int executed;
} IRStmt;

// ----------------- Internal structures -----------------
typedef struct Dependents {
    int *list;    // dynamic array of dependent indices
    int  capacity;
    int  count;
} Dependents;

typedef struct WorkQueue {
    int *buf;
    int capacity;
    int head;
    int tail;
    int size;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
} WorkQueue;

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
    q->buf = NULL;
    q->capacity = 0;
    q->head = q->tail = q->size = 0;
}

static void queue_push(WorkQueue *q, int val){
    pthread_mutex_lock(&q->mutex);
    // simple blocking assumption: capacity == number of stmts (never overfull)
    if(q->size >= q->capacity){
        // shouldn't happen; but avoid overflow by expanding (rare)
        int newcap = q->capacity * 2 + 16;
        int *nb = realloc(q->buf, sizeof(int) * newcap);
        if(!nb){ perror("realloc queue"); exit(EXIT_FAILURE); }
        // rotate old data if needed
        if(q->head <= q->tail) {
            // contiguous: nothing special
        } else {
            // move wrapped part to new contiguous layout
            memmove(nb + q->capacity + (q->head - q->tail), nb + q->head, sizeof(int) * (q->capacity - q->head));
            q->head = q->capacity + (q->head - q->tail);
        }
        q->tail = q->head + q->size;
        q->buf = nb;
        q->capacity = newcap;
    }
    q->buf[q->tail] = val;
    q->tail = (q->tail + 1) % q->capacity;
    q->size++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
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

// try pop without blocking; returns 1 if popped else 0
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

// ----------------- Executor implementation -----------------

typedef struct ExecContext {
    IRStmt* stmts;
    int stmt_count;
    VarSlot** env_array;
    int max_threads;

    // dependency tracking
    atomic_int *dep_remaining; // length stmt_count
    Dependents *dependents;    // length stmt_count

    WorkQueue queue;

    atomic_int remaining; // number of stmts left to execute
} ExecContext;

static void execute_single(IRStmt* s, VarSlot** env_array){
    if(s->dead || s->executed) return;

    // inlined simple sum semantics
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

    long *args = malloc(sizeof(long) * (s->argc > 0 ? s->argc : 1));
    if(!args){ perror("malloc args_values"); exit(EXIT_FAILURE); }
    for(int i=0;i<s->argc;i++){
        int ai = s->arg_indices[i];
        VarSlot* arg = env_array[ai];
        args[i] = arg->constant ? arg->value : (long)arg->data;
    }

    // call function ptr: expected signature void fn(long* lhs_ptr, long* args)
    void (*fn)(long*, long*) = s->func_ptr;
    VarSlot* lhs = env_array[s->lhs_index];

    pthread_mutex_lock(&lhs->lock);
    fn(&lhs->value, args);
    lhs->constant = 0;
    pthread_mutex_unlock(&lhs->lock);

    free(args);
    s->executed = 1;
}

// Worker thread main loop
static void* worker_thread(void* vctx){
    ExecContext* ctx = (ExecContext*)vctx;
    int idx;

    while(atomic_load(&ctx->remaining) > 0){
        // try to pop work; block if none available (but still exit when remaining==0)
        if(!queue_try_pop(&ctx->queue, &idx)){
            // check if we're done
            if(atomic_load(&ctx->remaining) <= 0) break;
            // blocking pop
            queue_pop_blocking(&ctx->queue, &idx);
        }

        IRStmt* s = &ctx->stmts[idx];

        if(s->dead || s->executed){
            // decrement remaining in case dead statements were pushed
            if(s->dead && !s->executed){
                // mark executed so won't be re-run (dead means no work)
                s->executed = 1;
                atomic_fetch_sub(&ctx->remaining, 1);
            }
            continue;
        }

        // execute it
        execute_single(s, ctx->env_array);

        // mark finished and notify dependents
        atomic_fetch_sub(&ctx->remaining, 1);

        // iterate dependents
        Dependents *deps = &ctx->dependents[idx];
        for(int di = 0; di < deps->count; ++di){
            int d = deps->list[di];
            int prev = atomic_fetch_sub(&ctx->dep_remaining[d], 1);
            // prev is the value before decrement; when prev==1 it reached zero
            if(prev == 1){
                // push dependent to queue
                queue_push(&ctx->queue, d);
            }
        }
    }

    return NULL;
}

// Build dependents arrays from dep_indices (predecessors)
static void build_dependents(ExecContext *ctx){
    int n = ctx->stmt_count;
    // first compute counts
    int *cnt = calloc(n, sizeof(int));
    if(!cnt){ perror("calloc dependents cnt"); exit(EXIT_FAILURE); }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred >= 0 && pred < n) cnt[pred]++; // pred has one more dependent
        }
    }

    ctx->dependents = malloc(sizeof(Dependents) * n);
    if(!ctx->dependents){ perror("malloc dependents"); exit(EXIT_FAILURE); }
    for(int i=0;i<n;i++){
        ctx->dependents[i].count = 0;
        ctx->dependents[i].capacity = cnt[i];
        if(cnt[i] > 0){
            ctx->dependents[i].list = malloc(sizeof(int) * cnt[i]);
            if(!ctx->dependents[i].list){ perror("malloc dependents.list"); exit(EXIT_FAILURE); }
        } else {
            ctx->dependents[i].list = NULL;
        }
    }

    // fill lists
    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred >= 0 && pred < n){
                Dependents *d = &ctx->dependents[pred];
                d->list[d->count++] = i;
            }
        }
    }
    free(cnt);
}

// free dependents
static void free_dependents(ExecContext *ctx){
    if(!ctx->dependents) return;
    for(int i=0;i<ctx->stmt_count;i++){
        if(ctx->dependents[i].list) free(ctx->dependents[i].list);
    }
    free(ctx->dependents);
    ctx->dependents = NULL;
}

// Main exported function: matches compiler expectation
// Note: this is the function the compiler will call via function pointer loaded from executor.bin
void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads){
    if(!stmts || stmt_count <= 0){
        return;
    }
    if(max_threads <= 0) max_threads = 1;

    ExecContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.stmts = stmts;
    ctx.stmt_count = stmt_count;
    ctx.env_array = env_array;
    ctx.max_threads = max_threads;

    // allocate dep_remaining
    ctx.dep_remaining = malloc(sizeof(atomic_int) * stmt_count);
    if(!ctx.dep_remaining){ perror("malloc dep_remaining"); exit(EXIT_FAILURE); }
    for(int i=0;i<stmt_count;i++){
        atomic_init(&ctx.dep_remaining[i], (int)stmts[i].dep_count);
    }

    // build dependents lists
    build_dependents(&ctx);

    // init remaining counter: count only real statements (non-dead)
    atomic_init(&ctx.remaining, 0);
    for(int i=0;i<stmt_count;i++){
        if(stmts[i].dead){
            // mark executed so won't be scheduled
            stmts[i].executed = 1;
        } else {
            atomic_fetch_add(&ctx.remaining, 1);
        }
    }

    // init queue with capacity = stmt_count
    queue_init(&ctx.queue, stmt_count + 8);

    // push all ready statements (dep_remaining == 0 and not dead)
    for(int i=0;i<stmt_count;i++){
        if(stmts[i].dead) continue;
        int rem = atomic_load(&ctx.dep_remaining[i]);
        if(rem == 0){
            queue_push(&ctx.queue, i);
        }
    }

    // create worker threads
    int nt = ctx.max_threads;
    pthread_t *threads = malloc(sizeof(pthread_t) * nt);
    if(!threads){ perror("malloc threads"); exit(EXIT_FAILURE); }
    for(int t=0;t<nt;t++){
        if(pthread_create(&threads[t], NULL, worker_thread, &ctx) != 0){
            perror("pthread_create");
            // if thread creation fails, adjust nt
            nt = t;
            break;
        }
    }

    // join threads
    for(int t=0;t<nt;t++){
        pthread_join(threads[t], NULL);
    }

    free(threads);

    // cleanup
    queue_destroy(&ctx.queue);
    free_dependents(&ctx);
    free(ctx.dep_remaining);

    // All statements executed (or dead). Return to caller.
}
