// executor_bin.c (ultimate micro-optimized)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sched.h>

#define MAX_ARGS 16
#define CACHE_LINE 64

typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    char pad[CACHE_LINE - sizeof(void*) - 4*4 - sizeof(long)];
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
    char pad[CACHE_LINE - 9*4 - sizeof(void*) - sizeof(int*)];
} IRStmt;

typedef struct Dependents {
    int* list;
    int capacity;
    int count;
} Dependents;

typedef struct WorkQueue {
    int *buf;
    int capacity;
    atomic_int head;
    atomic_int tail;
} WorkQueue;

typedef struct ExecContext {
    IRStmt* stmts;
    int stmt_count;
    VarSlot** env_array;
    int max_threads;
    atomic_int* dep_remaining;
    Dependents* dependents;
    atomic_int remaining;
    WorkQueue queue;
    VarSlot* varpool;
    int varpool_size;
    atomic_int pool_index;
} ExecContext;

// ---------------- Queue ----------------
static void queue_init(WorkQueue* q, int capacity){
    q->buf = malloc(sizeof(int)*capacity);
    if(!q->buf){ perror("malloc queue"); exit(EXIT_FAILURE); }
    q->capacity = capacity;
    atomic_init(&q->head,0);
    atomic_init(&q->tail,0);
}

static void queue_push(WorkQueue* q, int val){
    int tail = atomic_fetch_add(&q->tail, 1) % q->capacity;
    q->buf[tail] = val;
}

static int queue_try_pop(WorkQueue* q, int* out){
    int head = atomic_load(&q->head);
    int tail = atomic_load(&q->tail);
    if(head >= tail) return 0;
    if(atomic_compare_exchange_strong(&q->head, &head, head+1)){
        *out = q->buf[head % q->capacity];
        return 1;
    }
    return 0;
}

// ---------------- VarSlot pool ----------------
static void preacquire_varpool(ExecContext* ctx, int max_vars){
    ctx->varpool_size = max_vars;
    ctx->varpool = malloc(sizeof(VarSlot)*max_vars);
    if(!ctx->varpool){ perror("malloc varpool"); exit(EXIT_FAILURE); }
    atomic_init(&ctx->pool_index,0);
    for(int i=0;i<max_vars;i++){
        ctx->varpool[i].data = NULL;
        ctx->varpool[i].in_use = 0;
        ctx->varpool[i].last_use = 0;
        ctx->varpool[i].constant = 0;
        ctx->varpool[i].value = 0;
    }
}

static VarSlot* acquire_var(ExecContext* ctx){
    int idx = atomic_fetch_add(&ctx->pool_index,1);
    if(idx >= ctx->varpool_size) { fprintf(stderr,"VarSlot pool exhausted!\n"); return NULL; }
    VarSlot* v = &ctx->varpool[idx];
    v->in_use = 1;
    return v;
}

static void release_var(VarSlot* v){
    v->in_use = 0;
    v->data = NULL;
    v->constant = 0;
    v->value = 0;
}

// ---------------- Execute single ----------------
static void execute_single(IRStmt* s, ExecContext* ctx, long* args_buffer){
    if(s->dead || s->executed) return;

    for(int i=0;i<s->argc;i++){
        int ai = s->arg_indices[i];
        VarSlot* arg = ctx->env_array[ai];
        args_buffer[i] = arg->constant ? arg->value : (long)arg->data;
        if(arg->last_use == s - ctx->stmts) release_var(arg);
    }

    if(s->inlined){
        long val=0;
        for(int i=0;i<s->argc;i++) val+=args_buffer[i];
        VarSlot* lhs = ctx->env_array[s->lhs_index];
        lhs->value = val;
        lhs->constant = 0;
    } else if(s->func_ptr){
        void (*fn)(long*,long*) = s->func_ptr;
        VarSlot* lhs = ctx->env_array[s->lhs_index];
        fn(&lhs->value,args_buffer);
        lhs->constant = 0;
    }

    s->executed = 1;
}

// ---------------- Worker ----------------
static void* worker_thread(void* vctx){
    ExecContext* ctx = (ExecContext*)vctx;
    int idx;
    long args_buffer[MAX_ARGS];

    while(atomic_load(&ctx->remaining) > 0){
        if(!queue_try_pop(&ctx->queue,&idx)){
            sched_yield();
            continue;
        }

        IRStmt* s = &ctx->stmts[idx];
        execute_single(s,ctx,args_buffer);
        atomic_fetch_sub(&ctx->remaining,1);

        Dependents* deps = &ctx->dependents[idx];
        for(int di=0;di<deps->count;di++){
            int d = deps->list[di];
            int prev = atomic_fetch_sub(&ctx->dep_remaining[d],1);
            if(prev==1) queue_push(&ctx->queue,d);
        }
    }

    return NULL;
}

// ---------------- Dependents ----------------
static void build_dependents(ExecContext* ctx){
    int n = ctx->stmt_count;
    int* cnt = calloc(n,sizeof(int));
    if(!cnt){ perror("calloc cnt"); exit(EXIT_FAILURE); }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred>=0 && pred<n) cnt[pred]++;
        }
    }

    ctx->dependents = malloc(sizeof(Dependents)*n);
    if(!ctx->dependents){ perror("malloc dependents"); exit(EXIT_FAILURE); }

    for(int i=0;i<n;i++){
        ctx->dependents[i].count=0;
        ctx->dependents[i].capacity=cnt[i];
        ctx->dependents[i].list=cnt[i]?malloc(sizeof(int)*cnt[i]):NULL;
    }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred>=0 && pred<n){
                ctx->dependents[pred].list[ctx->dependents[pred].count++]=i;
            }
        }
    }

    free(cnt);
}

static void free_dependents(ExecContext* ctx){
    if(!ctx->dependents) return;
    for(int i=0;i<ctx->stmt_count;i++)
        if(ctx->dependents[i].list) free(ctx->dependents[i].list);
    free(ctx->dependents);
    ctx->dependents=NULL;
}

// ---------------- Main Executor ----------------
void executor(IRStmt* stmts,int stmt_count,VarSlot** env_array,int max_threads){
    if(!stmts || stmt_count<=0) return;
    if(max_threads<=0) max_threads=1;

    ExecContext ctx;
    memset(&ctx,0,sizeof(ctx));
    ctx.stmts=stmts;
    ctx.stmt_count=stmt_count;
    ctx.env_array=env_array;
    ctx.max_threads=max_threads;

    preacquire_varpool(&ctx, stmt_count*2);

    ctx.dep_remaining=malloc(sizeof(atomic_int)*stmt_count);
    if(!ctx.dep_remaining){ perror("malloc dep_remaining"); exit(EXIT_FAILURE); }
    for(int i=0;i<stmt_count;i++) atomic_init(&ctx.dep_remaining[i],stmts[i].dep_count);

    build_dependents(&ctx);

    atomic_init(&ctx.remaining,0);
    for(int i=0;i<stmt_count;i++){
        if(stmts[i].dead) stmts[i].executed=1;
        else atomic_fetch_add(&ctx.remaining,1);
    }

    queue_init(&ctx.queue, stmt_count+8);

    for(int i=0;i<stmt_count;i++)
        if(!stmts[i].dead && atomic_load(&ctx.dep_remaining[i])==0)
            queue_push(&ctx.queue,i);

    pthread_t* threads = malloc(sizeof(pthread_t)*max_threads);
    if(!threads){ perror("malloc threads"); exit(EXIT_FAILURE); }

    for(int t=0;t<max_threads;t++)
        pthread_create(&threads[t],NULL,worker_thread,&ctx);
    for(int t=0;t<max_threads;t++)
        pthread_join(threads[t],NULL);

    free(threads);
    free_dependents(&ctx);
    free(ctx.dep_remaining);
    free(ctx.queue.buf);
    free(ctx.varpool);
}
