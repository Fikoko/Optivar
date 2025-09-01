// orchestrator.c - superoptimized, fully merged
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sched.h>

#define MAX_NAME_LEN 128
#define MAX_THREADS 32
#define MAX_ARGS 16
#define CACHE_LINE 64

// ---------------- VarSlot ----------------
typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    char pad[CACHE_LINE - sizeof(void*) - 4*4 - sizeof(long)];
} VarSlot;

// ---------------- IR ----------------
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

// ---------------- Dependents ----------------
typedef struct Dependents {
    int* list;
    int capacity;
    int count;
} Dependents;

// ---------------- WorkQueue ----------------
typedef struct WorkQueue {
    int *buf;
    int capacity;
    atomic_int head;
    atomic_int tail;
} WorkQueue;

// ---------------- ExecContext ----------------
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

// ---------------- Function Table ----------------
typedef struct FuncEntry {
    char name[MAX_NAME_LEN];
    void* ptr;
    size_t len;
    size_t offset;
} FuncEntry;

static FuncEntry func_table[256];
static int func_count = 0;
static char* func_blob = NULL;
static size_t func_blob_size = 0;

// ---------------- Function Preload ----------------
static void preload_binfuncs(const char* dirpath){
    DIR* dir = opendir(dirpath);
    if(!dir) { perror("opendir"); return; }

    struct dirent* entry;
    size_t total_size = 0;

    while((entry = readdir(dir))!=NULL){
        if(entry->d_type!=DT_REG) continue;
        size_t len = strlen(entry->d_name);
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){
            char path[512]; snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            struct stat st;
            if(stat(path,&st)==0) total_size+=st.st_size;
        }
    }
    closedir(dir);
    if(total_size==0) return;

    func_blob = mmap(NULL,total_size,PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0);
    if(func_blob==MAP_FAILED){ perror("mmap"); func_blob=NULL; return; }
    func_blob_size = total_size;

    dir = opendir(dirpath); if(!dir){ perror("opendir"); return; }

    size_t offset = 0;
    while((entry = readdir(dir))!=NULL){
        if(entry->d_type!=DT_REG) continue;
        size_t len = strlen(entry->d_name);
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){
            char funcname[MAX_NAME_LEN];
            strncpy(funcname,entry->d_name,len-4); funcname[len-4]='\0';
            char path[512]; snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            FILE* f = fopen(path,"rb"); if(!f){ perror(path); continue; }
            fseek(f,0,SEEK_END); long flen=ftell(f); rewind(f);
            fread(func_blob+offset,1,(size_t)flen,f); fclose(f);

            func_table[func_count].ptr = func_blob+offset;
            strncpy(func_table[func_count].name,funcname,MAX_NAME_LEN-1);
            func_table[func_count].len = flen;
            func_table[func_count].offset = offset;
            offset+=flen; func_count++; if(func_count>=256) break;
        }
    }
    closedir(dir);
}

static void* get_func_ptr(const char* name){
    for(int i=0;i<func_count;i++)
        if(strcmp(func_table[i].name,name)==0) return func_table[i].ptr;
    return NULL;
}

// ---------------- Queue ----------------
static void queue_init(WorkQueue* q, int capacity){
    q->buf = malloc(sizeof(int)*capacity);
    if(!q->buf){ perror("malloc queue"); exit(1); }
    q->capacity = capacity;
    atomic_init(&q->head,0); atomic_init(&q->tail,0);
}

static void queue_push(WorkQueue* q, int val){
    int tail = atomic_fetch_add(&q->tail,1) % q->capacity;
    q->buf[tail] = val;
}

static int queue_try_pop(WorkQueue* q, int* out){
    int head = atomic_load(&q->head);
    int tail = atomic_load(&q->tail);
    if(head >= tail) return 0;
    if(atomic_compare_exchange_strong(&q->head,&head,head+1)){
        *out = q->buf[head % q->capacity];
        return 1;
    }
    return 0;
}

// ---------------- VarPool ----------------
static void preacquire_varpool(ExecContext* ctx,int max_vars){
    ctx->varpool_size = max_vars;
    ctx->varpool = malloc(sizeof(VarSlot)*max_vars);
    if(!ctx->varpool){ perror("malloc varpool"); exit(1); }
    atomic_init(&ctx->pool_index,0);
    for(int i=0;i<max_vars;i++){
        ctx->varpool[i].data=NULL; ctx->varpool[i].in_use=0;
        ctx->varpool[i].last_use=0; ctx->varpool[i].constant=0;
        ctx->varpool[i].value=0;
    }
}

static VarSlot* acquire_var(ExecContext* ctx){
    int idx = atomic_fetch_add(&ctx->pool_index,1);
    if(idx>=ctx->varpool_size){ fprintf(stderr,"VarSlot pool exhausted!\n"); return NULL; }
    VarSlot* v = &ctx->varpool[idx];
    v->in_use=1;
    return v;
}

static void release_var(VarSlot* v){
    v->in_use=0; v->data=NULL; v->constant=0; v->value=0;
}

// ---------------- Execute Single ----------------
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
        lhs->value = val; lhs->constant=0;
    } else if(s->func_ptr){
        void (*fn)(long*,long*) = s->func_ptr;
        VarSlot* lhs = ctx->env_array[s->lhs_index];
        fn(&lhs->value,args_buffer);
        lhs->constant=0;
    }

    s->executed=1;
}

// ---------------- Worker ----------------
static void* worker_thread(void* vctx){
    ExecContext* ctx = (ExecContext*)vctx;
    int idx; long args_buffer[MAX_ARGS];

    while(atomic_load(&ctx->remaining)>0){
        if(!queue_try_pop(&ctx->queue,&idx)){ sched_yield(); continue; }
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
    if(!cnt){ perror("calloc"); exit(1); }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred>=0 && pred<n) cnt[pred]++;
        }
    }

    ctx->dependents = malloc(sizeof(Dependents)*n);
    if(!ctx->dependents){ perror("malloc"); exit(1); }

    for(int i=0;i<n;i++){
        ctx->dependents[i].count=0;
        ctx->dependents[i].capacity=cnt[i];
        ctx->dependents[i].list=cnt[i]?malloc(sizeof(int)*cnt[i]):NULL;
    }

    for(int i=0;i<n;i++){
        IRStmt* s = &ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred = s->dep_indices[p];
            if(pred>=0 && pred<n)
                ctx->dependents[pred].list[ctx->dependents[pred].count++] = i;
        }
    }

    free(cnt);
}

static void free_dependents(ExecContext* ctx){
    if(!ctx->dependents) return;
    for(int i=0;i<ctx->stmt_count;i++)
        if(ctx->dependents[i].list) free(ctx->dependents[i].list);
    free(ctx->dependents); ctx->dependents=NULL;
}

// ---------------- Auto-link IR ----------------
static void link_ir_to_bin(IRStmt* stmts,int stmt_count){
    for(int i=0;i<stmt_count;i++){
        IRStmt* s=&stmts[i];
        if(s->func_ptr) continue; // already linked
        // Example: link by lhs_index
        char func_name[MAX_NAME_LEN];
        snprintf(func_name,MAX_NAME_LEN,"fn_%d",s->lhs_index);
        void* ptr = get_func_ptr(func_name);
        if(ptr) s->func_ptr = ptr;
    }
}

// ---------------- Orchestrator ----------------
void orchestrator_execute(IRStmt* stmts,int stmt_count,VarSlot** env_array,int max_threads){
    if(!stmts || stmt_count<=0) return;
    if(max_threads<=0) max_threads=1;
    if(max_threads>MAX_THREADS) max_threads=MAX_THREADS;

    ExecContext ctx; memset(&ctx,0,sizeof(ctx));
    ctx.stmts = stmts; ctx.stmt_count=stmt_count; ctx.env_array=env_array; ctx.max_threads=max_threads;

    preacquire_varpool(&ctx, stmt_count*2);

    ctx.dep_remaining = malloc(sizeof(atomic_int)*stmt_count);
    if(!ctx.dep_remaining){ perror("malloc"); exit(1); }
    for(int i=0;i<stmt_count;i++) atomic_init(&ctx.dep_remaining[i], stmts[i].dep_count);

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

    // Auto-link available .bin functions
    link_ir_to_bin(stmts,stmt_count);

    pthread_t threads[MAX_THREADS];
    for(int t=0;t<ctx.max_threads;t++)
        pthread_create(&threads[t],NULL,worker_thread,&ctx);
    for(int t=0;t<ctx.max_threads;t++)
        pthread_join(&threads[t],NULL);

    free_dependents(&ctx);
    free(ctx.dep_remaining);
    free(ctx.queue.buf);
    free(ctx.varpool);
}

// ---------------- Free Function Table ----------------
static void free_func_table(){
    if(func_blob) munmap(func_blob,func_blob_size);
    func_blob=NULL; func_blob_size=0; func_count=0;
}
