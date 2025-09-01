// optivar_orchestrator.c (superoptimized + adaptive unbounded)
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
#define VAR_TABLE_SIZE 2048
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
static VarSlot* var_table[VAR_TABLE_SIZE];

// ---------------- Hash function ----------------
static inline unsigned int hash_name(const char* s){
    unsigned int h = 0;
    while(*s) h = (h * 31) + (unsigned char)(*s++);
    return h % VAR_TABLE_SIZE;
}

// ---------------- Pool allocator ----------------
static VarSlot* pool_alloc(){
    for(int i=0;i<fixed_top;i++){
        if(!fixed_pool[i].in_use){
            fixed_pool[i].in_use=1;
            fixed_pool[i].last_use=-1;
            fixed_pool[i].constant=0;
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
                chunk->slots[i].in_use=1;
                chunk->slots[i].last_use=-1;
                chunk->slots[i].constant=0;
                return &chunk->slots[i];
            }
        }
        chunk=chunk->next;
    }
    // allocate new chunk dynamically
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
            char path[512];
            snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            struct stat st;
            if(stat(path,&st)==0) total_size+=(size_t)st.st_size;
        }
    }
    closedir(dir);
    if(total_size==0) return;

    func_blob = mmap(NULL,total_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0);
    if(func_blob==MAP_FAILED){ perror("mmap func_blob"); func_blob=NULL; return; }
    func_blob_size = total_size;

    dir=opendir(dirpath);
    if(!dir){ perror("opendir"); return; }
    size_t offset=0;
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type!=DT_REG) continue;
        size_t len=strlen(entry->d_name);
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){
            char funcname[MAX_NAME_LEN];
            strncpy(funcname,entry->d_name,len-4);
            funcname[len-4]='\0';
            char path[512]; snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            FILE* f=fopen(path,"rb");
            if(!f){ perror(path); continue;}
            fseek(f,0,SEEK_END);
            long flen=ftell(f); rewind(f);
            fread(func_blob+offset,1,(size_t)flen,f);
            fclose(f);
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

static void free_func_table(){
    if(func_blob) munmap(func_blob,func_blob_size);
    func_blob=NULL; func_blob_size=0; func_count=0;
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

// ---------------- Variable table ----------------
static int var_index(const char* name){
    unsigned int h=hash_name(name);
    for(int i=0;i<VAR_TABLE_SIZE;i++){
        unsigned int idx=(h+i)%VAR_TABLE_SIZE;
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
    // fallback dynamic hash growth could be implemented here if needed
    return -1;
}

// ---------------- Parser ----------------
static inline int is_space(char c){ return c==' '||c=='\t'||c=='\n'||c=='\r'; }

static IRStmt parse_statement(char* stmt){
    IRStmt s; memset(&s,0,sizeof(IRStmt));
    char* comment=strstr(stmt,"--"); if(comment)*comment='\0';
    while(*stmt && is_space(*stmt)) stmt++;
    if(!*stmt) return s;
    char* eq=strchr(stmt,'='); if(!eq) return s; *eq='\0';
    char* lhs=stmt; while(is_space(*lhs)) lhs++;
    char* lhs_end=lhs+strlen(lhs)-1; while(lhs_end>lhs && is_space(*lhs_end))*lhs_end--='\0';
    s.lhs_index=var_index(lhs);
    char* rhs=eq+1; while(*rhs && is_space(*rhs)) rhs++;
    char* paren=strchr(rhs,'('); if(!paren) return s; *paren='\0';
    char* funcname=rhs;
    char* fend=funcname+strlen(funcname)-1; while(fend>funcname && is_space(*fend))*fend--='\0';
    for(int i=0;i<func_count;i++){ if(strcmp(func_table[i].name,funcname)==0){ s.func_ptr=func_table[i].ptr; if(func_table[i].len<=INLINE_THRESHOLD)s.inlined=1; break;}}
    char* args_str=paren+1;
    char* close=strrchr(args_str,')'); if(!close) return s; *close='\0';
    int arg_cap=16; s.arg_indices=arg_alloc(arg_cap); s.argc=0;
    char* p=args_str;
    while(*p){
        while(is_space(*p)) p++;
        if(*p==','){p++; continue;}
        char* start=p; while(*p && *p!=',' && *p!=')') p++;
        char* end=p-1; while(end>start && is_space(*end))*end--='\0';
        if(p>start){
            if(s.argc>=arg_cap){ arg_cap*=2; int* new_args=arg_alloc(arg_cap); memcpy(new_args,s.arg_indices,sizeof(int)*s.argc); s.arg_indices=new_args;}
            char tmp[256]; int len=(int)(end-start+1); if(len>=256) len=255; memcpy(tmp,start,len); tmp[len]='\0';
            char* t=tmp; while(is_space(*t)) t++;
            s.arg_indices[s.argc++]=var_index(t);
        }
        if(*p==',') p++;
    }
    return s;
}

// ---------------- Optimizations ----------------
static void constant_folding(IR* ir){
    for(int i=0;i<ir->count;i++){
        IRStmt* s=&ir->stmts[i];
        if(s->dead || !s->func_ptr) continue;
        int all_const=1; long val=0;
        for(int j=0;j<s->argc;j++){
            int ai=s->arg_indices[j];
            if(ai<0 || ai>=var_count || !env_array[ai]->constant){ all_const=0; break;}
            val+=env_array[ai]->value;
        }
        if(all_const){ env_array[s->lhs_index]->constant=1; env_array[s->lhs_index]->value=val; s->func_ptr=NULL;}
    }
}

static void dead_code_elimination(IR* ir){
    if(var_count==0) return;
    int* used=calloc(var_count,sizeof(int));
    for(int i=ir->count-1;i>=0;i--){
        IRStmt* s=&ir->stmts[i];
        if(!s->func_ptr) continue;
        if(!used[s->lhs_index]) s->dead=1;
        for(int j=0;j<s->argc;j++) used[s->arg_indices[j]]=1;
    }
    free(used);
}

static void ir_batching(IR* ir){
    for(int i=0;i<ir->count-1;i++){
        IRStmt* s=&ir->stmts[i]; if(s->dead||!s->func_ptr) continue;
        IRStmt* next=&ir->stmts[i+1]; if(next->dead||!next->func_ptr) continue;
        if(s->func_ptr==next->func_ptr){
            int total=s->argc+next->argc; int* merged=arg_alloc(total);
            memcpy(merged,s->arg_indices,sizeof(int)*s->argc);
            memcpy(merged+s->argc,next->arg_indices,sizeof(int)*next->argc);
            s->arg_indices=merged; s->argc=total; next->dead=1;
        }
    }
}

static void build_dependencies(IR* ir){
    for(int i=0;i<ir->count;i++){
        IRStmt* s=&ir->stmts[i]; s->dep_count=0; s->dep_indices=NULL; s->executed=0;
        int dep_cap=4; int* deps=malloc(sizeof(int)*dep_cap); int deps_used=0;
        for(int j=0;j<i;j++){
            IRStmt* prev=&ir->stmts[j];
            for(int k=0;k<s->argc;k++){
                if(prev->lhs_index==s->arg_indices[k]){
                    if(deps_used>=dep_cap){ dep_cap*=2; int* tmp=realloc(deps,sizeof(int)*dep_cap); deps=tmp;}
                    deps[deps_used++]=j; break;
                }
            }
        }
        if(deps_used){ s->dep_indices=deps; s->dep_count=deps_used;} else free(deps);
    }
}

// ---------------- Environment ----------------
static void init_env(int total_vars){
    env_alloc_size=total_vars>0? total_vars:(FIXED_VARS*2);
    env_array=malloc(sizeof(VarSlot*)*env_alloc_size);
    memset(env_array,0,sizeof(VarSlot*)*env_alloc_size);
}

// ---------------- Executor ----------------
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
    if(!stmts||stmt_count<=0) return;
    if(max_threads<=0) max_threads=1;
    ExecContext ctx; memset(&ctx,0,sizeof(ctx));
    ctx.stmts=stmts; ctx.stmt_count=stmt_count; ctx.env_array=env_array; ctx.max_threads=max_threads;
    ctx.dep_remaining=malloc(sizeof(atomic_int)*stmt_count);
    for(int i=0;i<stmt_count;i++) atomic_init(&ctx.dep_remaining[i],stmts[i].dep_count);
    build_dependents(&ctx);
    atomic_init(&ctx.remaining,0);
    for(int i=0;i<stmt_count;i++){ if(stmts[i].dead) stmts[i].executed=1; else atomic_fetch_add(&ctx.remaining,1);}
    queue_init(&ctx.queue,stmt_count+8);
    for(int i=0;i<stmt_count;i++) if(!stmts[i].dead && atomic_load(&ctx.dep_remaining[i])==0) queue_push(&ctx.queue,i);
    pthread_t* threads=malloc(sizeof(pthread_t)*max_threads);
    for(int t=0;t<max_threads;t++) pthread_create(&threads[t],NULL,worker_thread,&ctx);
    for(int t=0;t<max_threads;t++) pthread_join(threads[t],NULL);
    free(threads); free_dependents(&ctx); free(ctx.dep_remaining); free(ctx.queue.buf);
}
