// optivar_orchestrator.c (fully adaptive + unbounded)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <stdatomic.h>
#include <sched.h>

#define MAX_IR 8192
#define FIXED_VARS 1024
#define VAR_CHUNK_SIZE 2048
#define FIXED_ARG_POOL 128
#define INLINE_THRESHOLD 3
#define MAX_NAME_LEN 128
#define CACHE_LINE 64
#define MAX_ARGS 16

// ---------------- VarSlot ----------------
typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    char pad[CACHE_LINE - sizeof(void*) - 4*4 - sizeof(long)];
} VarSlot;

// ---------------- IRStmt ----------------
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

// ---------------- Pools ----------------
static VarSlot fixed_pool[FIXED_VARS];
static int fixed_top = 0;

typedef struct VarPoolChunk {
    VarSlot* slots;
    int capacity;
    struct VarPoolChunk* next;
} VarPoolChunk;
static VarPoolChunk* dynamic_pool = NULL;

// ---------------- Environment ----------------
static VarSlot** env_array = NULL;
static int var_count = 0;
static int env_alloc_size = 0;

// ---------------- Hash table ----------------
static VarSlot** var_table = NULL;
static int var_table_size = 2048;

// ---------------- Hash function ----------------
static inline unsigned int hash_name(const char* s, int table_size){
    unsigned int h = 0;
    while(*s) h = (h * 31) + (unsigned char)(*s++);
    return h % table_size;
}

// ---------------- Pool allocator ----------------
static VarSlot* pool_alloc(){
    for(int i=0;i<fixed_top;i++){
        if(!fixed_pool[i].in_use){
            fixed_pool[i].in_use=1; fixed_pool[i].last_use=-1; fixed_pool[i].constant=0;
            return &fixed_pool[i];
        }
    }
    if(fixed_top < FIXED_VARS){
        VarSlot* slot = &fixed_pool[fixed_top++];
        slot->in_use=1; slot->last_use=-1; slot->constant=0;
        return slot;
    }
    VarPoolChunk* chunk = dynamic_pool;
    while(chunk){
        for(int i=0;i<chunk->capacity;i++){
            if(!chunk->slots[i].in_use){
                chunk->slots[i].in_use=1; chunk->slots[i].last_use=-1; chunk->slots[i].constant=0;
                return &chunk->slots[i];
            }
        }
        chunk=chunk->next;
    }
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* new_chunk = malloc(sizeof(VarPoolChunk));
    if(!new_chunk){ perror("malloc VarPoolChunk"); exit(EXIT_FAILURE);}
    new_chunk->slots = calloc(cap,sizeof(VarSlot));
    if(!new_chunk->slots){ perror("calloc VarPoolChunk->slots"); exit(EXIT_FAILURE);}
    new_chunk->capacity = cap;
    new_chunk->next = dynamic_pool;
    dynamic_pool = new_chunk;
    new_chunk->slots[0].in_use=1; new_chunk->slots[0].last_use=-1; new_chunk->slots[0].constant=0;
    return &new_chunk->slots[0];
}

// ---------------- Function table ----------------
typedef struct {
    char name[MAX_NAME_LEN];
    void* ptr;
    size_t len;
    size_t offset;
} FuncEntry;

static FuncEntry func_table[256];
static int func_count = 0;
static char* func_blob = NULL;
static size_t func_blob_size = 0;

// ---------------- Preload .bin functions ----------------
static void preload_binfuncs(const char* dirpath){
    DIR* dir = opendir(dirpath);
    if(!dir){ perror("opendir"); return; }
    struct dirent* entry;
    size_t total_size=0;
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type!=DT_REG) continue;
        size_t len=strlen(entry->d_name);
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){
            char path[512]; snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            struct stat st; if(stat(path,&st)==0) total_size+=st.st_size;
        }
    }
    closedir(dir);
    if(total_size==0) return;
    func_blob = mmap(NULL,total_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0);
    if(func_blob==MAP_FAILED){ perror("mmap func_blob"); func_blob=NULL; return; }
    func_blob_size = total_size;

    dir=opendir(dirpath); if(!dir){ perror("opendir"); return; }
    size_t offset=0;
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type!=DT_REG) continue;
        size_t len=strlen(entry->d_name);
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){
            char funcname[MAX_NAME_LEN]; strncpy(funcname,entry->d_name,len-4); funcname[len-4]='\0';
            char path[512]; snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            FILE* f=fopen(path,"rb"); if(!f){ perror(path); continue;}
            fseek(f,0,SEEK_END); long flen=ftell(f); rewind(f);
            fread(func_blob+offset,1,(size_t)flen,f); fclose(f);
            if(func_count>=256) break;
            strncpy(func_table[func_count].name,funcname,MAX_NAME_LEN-1);
            func_table[func_count].name[MAX_NAME_LEN-1]='\0';
            func_table[func_count].ptr=func_blob+offset;
            func_table[func_count].len=(size_t)flen;
            func_table[func_count].offset=offset;
            offset+=(size_t)flen;
            func_count++;
        }
    }
    closedir(dir);
}

// ---------------- IR ----------------
typedef struct IR{
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

static void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }

static IRStmt* ir_alloc_stmt(IR* ir){
    if(ir->count>=ir->capacity){
        int newcap=ir->capacity? ir->capacity*2:8;
        IRStmt* tmp=realloc(ir->stmts,sizeof(IRStmt)*newcap);
        if(!tmp){ perror("realloc IR"); exit(EXIT_FAILURE);}
        ir->stmts=tmp; ir->capacity=newcap;
    }
    IRStmt* s=&ir->stmts[ir->count++];
    memset(s,0,sizeof(IRStmt));
    return s;
}

// ---------------- ArgBlock ----------------
typedef struct ArgBlock{
    int* args;
    int capacity;
    int used;
    struct ArgBlock* next;
} ArgBlock;

static ArgBlock* arg_blocks=NULL;

static int* arg_alloc(int n){
    ArgBlock* b=arg_blocks;
    while(b){ if(b->capacity-b->used>=n){ int* ptr=b->args+b->used; b->used+=n; return ptr;} b=b->next; }
    int cap=(n>FIXED_ARG_POOL)? n: FIXED_ARG_POOL;
    ArgBlock* nb=malloc(sizeof(ArgBlock));
    nb->args=malloc(sizeof(int)*cap);
    nb->capacity=cap; nb->used=n; nb->next=arg_blocks; arg_blocks=nb;
    return nb->args;
}

static void free_arg_blocks(){
    ArgBlock* b=arg_blocks;
    while(b){ ArgBlock* nx=b->next; free(b->args); free(b); b=nx; }
    arg_blocks=NULL;
}

// ---------------- Dynamic var table ----------------
static void grow_var_table(){
    int new_size = var_table_size*2;
    VarSlot** new_table = calloc(new_size,sizeof(VarSlot*));
    for(int i=0;i<var_table_size;i++){
        if(var_table[i]){
            unsigned int h = hash_name((char*)var_table[i]->data,new_size);
            for(int j=0;j<new_size;j++){
                int idx=(h+j)%new_size;
                if(!new_table[idx]){ new_table[idx]=var_table[i]; break;}
            }
        }
    }
    free(var_table);
    var_table=new_table; var_table_size=new_size;
}

static int var_index(const char* name){
    if(!var_table){ var_table=calloc(var_table_size,sizeof(VarSlot*)); }
    unsigned int h=hash_name(name,var_table_size);
    for(int i=0;i<var_table_size;i++){
        unsigned int idx=(h+i)%var_table_size;
        if(!var_table[idx]){
            VarSlot* slot=pool_alloc();
            slot->data=strdup(name);
            var_table[idx]=slot;
            if(var_count>=env_alloc_size){
                int new_size=env_alloc_size? env_alloc_size*2: (FIXED_VARS*2);
                VarSlot** new_env=realloc(env_array,sizeof(VarSlot*)*new_size);
                env_array=new_env; env_alloc_size=new_size;
            }
            env_array[var_count]=slot;
            return var_count++;
        }
        if(strcmp((char*)var_table[idx]->data,name)==0){
            for(int j=0;j<var_count;j++) if(env_array[j]==var_table[idx]) return j;
        }
    }
    grow_var_table();
    return var_index(name);
}

// ---------------- Environment ----------------
static void init_env(int total_vars){
    env_alloc_size=total_vars>0? total_vars:(FIXED_VARS*2);
    env_array=malloc(sizeof(VarSlot*)*env_alloc_size);
    memset(env_array,0,sizeof(VarSlot*)*env_alloc_size);
}

// ---------------- Executor structures ----------------
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
} ExecContext;

// ---------------- Queue ----------------
static void queue_init(WorkQueue* q, int capacity){
    q->buf=malloc(sizeof(int)*capacity);
    q->capacity=capacity;
    atomic_init(&q->head,0); atomic_init(&q->tail,0);
}

static void queue_push(WorkQueue* q,int val){
    int tail=atomic_fetch_add(&q->tail,1)%q->capacity;
    q->buf[tail]=val;
}

static int queue_try_pop(WorkQueue* q,int* out){
    int head=atomic_load(&q->head);
    int tail=atomic_load(&q->tail);
    if(head>=tail) return 0;
    if(atomic_compare_exchange_strong(&q->head,&head,head+1)){ *out=q->buf[head%q->capacity]; return 1;}
    return 0;
}

// ---------------- Executor ----------------
static void execute_single(IRStmt* s, ExecContext* ctx,long* args_buffer){
    if(s->dead || s->executed) return;
    for(int i=0;i<s->argc;i++){
        int ai=s->arg_indices[i];
        VarSlot* arg=ctx->env_array[ai];
        args_buffer[i]=arg->constant? arg->value:(long)arg->data;
    }
    VarSlot* lhs=ctx->env_array[s->lhs_index];
    if(s->inlined){
        long val=0; for(int i=0;i<s->argc;i++) val+=args_buffer[i];
        lhs->value=val; lhs->constant=0;
    } else if(s->func_ptr){
        void (*fn)(long*,long*)=s->func_ptr;
        fn(&lhs->value,args_buffer);
        lhs->constant=0;
    }
    s->executed=1;
}

static void* worker_thread(void* vctx){
    ExecContext* ctx=(ExecContext*)vctx;
    long args_buffer[MAX_ARGS]; int idx;
    while(atomic_load(&ctx->remaining)>0){
        if(!queue_try_pop(&ctx->queue,&idx)){ sched_yield(); continue;}
        execute_single(&ctx->stmts[idx],ctx,args_buffer);
        atomic_fetch_sub(&ctx->remaining,1);
        Dependents* deps=&ctx->dependents[idx];
        for(int di=0;di<deps->count;di++){
            int d=deps->list[di];
            int prev=atomic_fetch_sub(&ctx->dep_remaining[d],1);
            if(prev==1) queue_push(&ctx->queue,d);
        }
    }
    return NULL;
}

static void build_dependents(ExecContext* ctx){
    int n=ctx->stmt_count;
    int* cnt=calloc(n,sizeof(int));
    for(int i=0;i<n;i++){
        IRStmt* s=&ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred=s->dep_indices[p]; if(pred>=0 && pred<n) cnt[pred]++;
        }
    }
    ctx->dependents=malloc(sizeof(Dependents)*n);
    for(int i=0;i<n;i++){
        ctx->dependents[i].count=0; ctx->dependents[i].capacity=cnt[i];
        ctx->dependents[i].list=cnt[i]?malloc(sizeof(int)*cnt[i]):NULL;
    }
    for(int i=0;i<n;i++){
        IRStmt* s=&ctx->stmts[i];
        for(int p=0;p<s->dep_count;p++){
            int pred=s->dep_indices[p]; if(pred>=0 && pred<n)
                ctx->dependents[pred].list[ctx->dependents[pred].count++]=i;
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

void executor(IRStmt* stmts,int stmt_count,VarSlot** env_array,int max_threads){
    ExecContext ctx={0};
    ctx.stmts=stmts; ctx.stmt_count=stmt_count; ctx.env_array=env_array; ctx.max_threads=max_threads;
    ctx.dep_remaining=calloc(stmt_count,sizeof(atomic_int));
    for(int i=0;i<stmt_count;i++) atomic_init(&ctx.dep_remaining[i],stmts[i].dep_count);
    build_dependents(&ctx);

    queue_init(&ctx.queue,stmt_count>1024?stmt_count*2:1024);
    for(int i=0;i<stmt_count;i++) if(stmts[i].dep_count==0) queue_push(&ctx.queue,i);

    atomic_init(&ctx.remaining,stmt_count);
    pthread_t* threads=malloc(sizeof(pthread_t)*max_threads);
    for(int i=0;i<max_threads;i++) pthread_create(&threads[i],NULL,worker_thread,&ctx);
    for(int i=0;i<max_threads;i++) pthread_join(threads[i],NULL);

    free(threads);
    free(ctx.dep_remaining);
    free_dependents(&ctx);
    free(ctx.queue.buf);
}

// ---------------- Init environment ----------------
static void init_full_env(int total_vars){
    init_env(total_vars);
}

// ---------------- Cleanup ----------------
static void cleanup(){
    free_arg_blocks();
    if(env_array){ free(env_array); env_array=NULL;}
    if(var_table){ free(var_table); var_table=NULL;}
    VarPoolChunk* c=dynamic_pool;
    while(c){ VarPoolChunk* nx=c->next; free(c->slots); free(c); c=nx;}
    dynamic_pool=NULL;
    if(func_blob) munmap(func_blob,func_blob_size);
}

