// optivar_compiler_superoptimized.c
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

#define MAX_IR 8192
#define FIXED_VARS 1024
#define VAR_CHUNK_SIZE 2048  // bigger chunks to reduce allocations
#define FIXED_ARG_POOL 128   // larger pool to reduce realloc
#define INLINE_THRESHOLD 3
#define MAX_NAME_LEN 128
#define VAR_TABLE_SIZE 2048

typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    pthread_mutex_t lock;
} VarSlot;

static VarSlot fixed_pool[FIXED_VARS];
static int fixed_top = 0;

typedef struct VarPoolChunk {
    VarSlot* slots;
    int capacity;
    struct VarPoolChunk* next;
} VarPoolChunk;
static VarPoolChunk* dynamic_pool = NULL;

static VarSlot** env_array = NULL;
static int var_count = 0;
static int env_alloc_size = 0;

static VarSlot* var_table[VAR_TABLE_SIZE];

static inline unsigned int hash_name(const char* s){
    unsigned int h = 0;
    while(*s) h = (h * 31) + (unsigned char)(*s++);
    return h % VAR_TABLE_SIZE;
}

// fast allocation with bitmap-like scan
static VarSlot* pool_alloc(){
    for(int i=0;i<fixed_top;i++){
        if(!fixed_pool[i].in_use){
            fixed_pool[i].in_use = 1;
            fixed_pool[i].last_use = -1;
            fixed_pool[i].constant = 0;
            return &fixed_pool[i];
        }
    }
    if(fixed_top < FIXED_VARS){
        VarSlot* slot = &fixed_pool[fixed_top++];
        slot->in_use = 1; slot->last_use = -1; slot->constant = 0;
        return slot;
    }
    VarPoolChunk* chunk = dynamic_pool;
    while(chunk){
        for(int i=0;i<chunk->capacity;i++){
            if(!chunk->slots[i].in_use){
                chunk->slots[i].in_use = 1;
                chunk->slots[i].last_use = -1;
                chunk->slots[i].constant = 0;
                return &chunk->slots[i];
            }
        }
        chunk = chunk->next;
    }
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* new_chunk = malloc(sizeof(VarPoolChunk));
    if(!new_chunk){ perror("malloc VarPoolChunk"); exit(EXIT_FAILURE); }
    new_chunk->slots = calloc(cap, sizeof(VarSlot));
    if(!new_chunk->slots){ perror("calloc VarPoolChunk->slots"); exit(EXIT_FAILURE); }
    new_chunk->capacity = cap;
    new_chunk->next = dynamic_pool;
    dynamic_pool = new_chunk;
    for(int i=0;i<cap;i++) pthread_mutex_init(&new_chunk->slots[i].lock, NULL);
    new_chunk->slots[0].in_use = 1;
    new_chunk->slots[0].last_use = -1;
    new_chunk->slots[0].constant = 0;
    return &new_chunk->slots[0];
}

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

// preload .bin functions using single mmap and avoiding multiple fseek/stat
static void preload_binfuncs(const char* dirpath){
    DIR* dir = opendir(dirpath);
    if(!dir){ perror("opendir"); return; }
    struct dirent* entry;
    size_t total_size = 0;

    while((entry = readdir(dir)) != NULL){
        if(entry->d_type != DT_REG) continue;
        size_t len = strlen(entry->d_name);
        if(len > 4 && strcmp(entry->d_name + len - 4, ".bin") == 0){
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);
            struct stat st;
            if(stat(path, &st) == 0) total_size += (size_t)st.st_size;
        }
    }
    closedir(dir);
    if(total_size == 0) return;

    func_blob = mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if(func_blob == MAP_FAILED){ perror("mmap func_blob"); func_blob = NULL; return; }
    func_blob_size = total_size;

    dir = opendir(dirpath);
    if(!dir){ perror("opendir"); return; }
    size_t offset = 0;
    while((entry = readdir(dir)) != NULL){
        if(entry->d_type != DT_REG) continue;
        size_t len = strlen(entry->d_name);
        if(len > 4 && strcmp(entry->d_name + len - 4, ".bin") == 0){
            char funcname[MAX_NAME_LEN];
            strncpy(funcname, entry->d_name, len-4);
            funcname[len-4] = '\0';
            char path[512]; snprintf(path,sizeof(path), "%s/%s", dirpath, entry->d_name);
            FILE* f = fopen(path, "rb");
            if(!f){ perror(path); continue; }
            fseek(f, 0, SEEK_END);
            long flen = ftell(f); rewind(f);
            fread(func_blob+offset, 1, (size_t)flen, f);
            fclose(f);
            if(func_count >= 256) break;
            strncpy(func_table[func_count].name, funcname, MAX_NAME_LEN-1);
            func_table[func_count].name[MAX_NAME_LEN-1]='\0';
            func_table[func_count].ptr = func_blob+offset;
            func_table[func_count].len = (size_t)flen;
            func_table[func_count].offset = offset;
            offset += (size_t)flen;
            func_count++;
        }
    }
    closedir(dir);
}

static void free_func_table(){
    if(func_blob) munmap(func_blob, func_blob_size);
    func_blob = NULL; func_blob_size = 0; func_count = 0;
}

// -------------------- IR --------------------
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

typedef struct IR {
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

static void ir_init(IR* ir){ ir->stmts = NULL; ir->count=ir->capacity=0; }

static IRStmt* ir_alloc_stmt(IR* ir){
    if(ir->count>=ir->capacity){
        int newcap = ir->capacity? ir->capacity*2:8;
        IRStmt* tmp = realloc(ir->stmts, sizeof(IRStmt)*newcap);
        if(!tmp){ perror("realloc IR"); exit(EXIT_FAILURE);}
        ir->stmts=tmp; ir->capacity=newcap;
    }
    IRStmt* s = &ir->stmts[ir->count++];
    memset(s,0,sizeof(IRStmt));
    return s;
}

// -------------------- ArgBlocks --------------------
typedef struct ArgBlock{
    int* args;
    int capacity;
    int used;
    struct ArgBlock* next;
} ArgBlock;

static ArgBlock* arg_blocks = NULL;

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

// -------------------- Variable Table --------------------
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
    return -1;
}

// -------------------- Parser --------------------
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

// -------------------- Optimizations --------------------
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

// -------------------- Environment --------------------
static void init_env(int total_vars){
    env_alloc_size=total_vars>0? total_vars:(FIXED_VARS*2);
    env_array=malloc(sizeof(VarSlot*)*env_alloc_size);
    for(int i=0;i<env_alloc_size;i++){
        env_array[i]=malloc(sizeof(VarSlot));
        env_array[i]->data=NULL; env_array[i]->in_use=0; env_array[i]->last_use=-1;
        env_array[i]->constant=0; env_array[i]->value=0;
    }
    var_count=0;
}

static void free_env(){
    for(int i=0;i<var_count;i++){
        if(env_array[i]->data) free(env_array[i]->data);
        free(env_array[i]);
    }
    for(int i=var_count;i<env_alloc_size;i++){ if(env_array[i]) free(env_array[i]); }
    free(env_array); env_array=NULL; env_alloc_size=0; var_count=0;
}

// -------------------- External executor --------------------
extern void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads);

// -------------------- Main --------------------
int main(int argc,char** argv){
    if(argc<3){ fprintf(stderr,"Usage: %s input.optivar binfuncs_dir\n",argv[0]); return 1; }
    init_env(FIXED_VARS*2);
    preload_binfuncs(argv[2]);

    FILE* f=fopen(argv[1],"r"); if(!f){ perror("fopen input"); return 1; }
    fseek(f,0,SEEK_END); long len=ftell(f); rewind(f);
    char* buf=mmap(NULL,(size_t)len+1,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    fread(buf,1,(size_t)len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* saveptr=NULL;
    char* tok=strtok_r(buf,";",&saveptr);
    int stmt_index=0;
    while(tok){
        IRStmt s=parse_statement(tok);
        for(int i=0;i<s.argc;i++){ int ai=s.arg_indices[i]; if(ai>=0 && ai<var_count) env_array[ai]->last_use=stmt_index; }
        IRStmt* dst=ir_alloc_stmt(&ir); *dst=s;
        tok=strtok_r(NULL,";",&saveptr); stmt_index++;
    }
    munmap(buf,(size_t)len+1);

    constant_folding(&ir);
    dead_code_elimination(&ir);
    ir_batching(&ir);
    build_dependencies(&ir);

    void (*bin_exec)(IRStmt*,int,VarSlot**,int)=NULL;
    for(int i=0;i<func_count;i++){ if(strcmp(func_table[i].name,"executor")==0){ bin_exec=func_table[i].ptr; break; } }
    if(!bin_exec && func_count>0) bin_exec=func_table[0].ptr;
    if(bin_exec) bin_exec(ir.stmts,ir.count,env_array,8);
    else { #ifdef HAVE_LINKED_EXECUTOR executor(ir.stmts,ir.count,env_array,8); #else fprintf(stderr,"No executor found.\n"); #endif }

    for(int i=0;i<var_count;i++) printf("Var %d = %ld\n",i,env_array[i]->value);
    for(int i=0;i<ir.count;i++) if(ir.stmts[i].arg_indices) free(ir.stmts[i].arg_indices);
    free_arg_blocks(); free_env(); free_func_table(); free(ir.stmts);
    return 0;
}
