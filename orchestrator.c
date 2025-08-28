// orchestrator_precompiled_ir.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <dirent.h>

#define MAX_VARS 1024
#define POOL_SIZE 1024
#define FUNC_HASH_SIZE 256
#define MAX_ARGS 8

typedef struct Var { void* data; } Var;
typedef Var* (*varfunc_t)(Var** args,int argc);

typedef struct {
    Var pool[POOL_SIZE];
    int top;
} VarPool;

static VarPool var_pool;
static void pool_init(){ var_pool.top=0; }
static Var* pool_alloc(){ if(var_pool.top<POOL_SIZE) return &var_pool.pool[var_pool.top++]; return malloc(sizeof(Var)); }
static void pool_reset(){ var_pool.top=0; }

static Var* env_array[MAX_VARS];

// ---------------- Function Hash ----------------
typedef struct FuncEntry {
    char* name;
    varfunc_t func;
    void* buf;
    size_t len;
    struct FuncEntry* next;
} FuncEntry;

static FuncEntry* func_hash[FUNC_HASH_SIZE];

static unsigned int hash_funcname(const char* s){
    unsigned int h=5381; while(*s) h=((h<<5)+h)+(unsigned char)(*s++); return h%FUNC_HASH_SIZE;
}

static void insert_func(FuncEntry* f){
    unsigned int h=hash_funcname(f->name);
    f->next=func_hash[h]; func_hash[h]=f;
}

static varfunc_t get_func(const char* name){
    unsigned int h=hash_funcname(name); FuncEntry* e=func_hash[h];
    while(e){ if(strcmp(e->name,name)==0) return e->func; e=e->next; }
    return NULL;
}

static void preload_binfuncs(const char* dirpath){
    DIR* dir=opendir(dirpath); if(!dir){ perror("opendir"); return; }
    struct dirent* entry;
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type==DT_REG){
            char* name=entry->d_name; size_t len=strlen(name);
            if(len>4 && strcmp(name+len-4,".bin")==0){
                char funcname[256]; strncpy(funcname,name,len-4); funcname[len-4]='\0';
                char path[256]; snprintf(path,sizeof(path),"%s/%s.bin",dirpath,funcname);
                FILE* f=fopen(path,"rb"); if(!f){ perror(path); continue; }
                fseek(f,0,SEEK_END); long flen=ftell(f); fseek(f,0,SEEK_SET);
                void* buf=mmap(NULL,flen,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
                if(!buf){ fclose(f); perror("mmap"); continue; }
                if(fread(buf,1,flen,f)!=flen){ fclose(f); munmap(buf,flen); continue; }
                fclose(f);

                FuncEntry* fe=malloc(sizeof(FuncEntry));
                fe->name=strdup(funcname);
                fe->func=(varfunc_t)buf;
                fe->buf=buf;
                fe->len=flen;
                fe->next=NULL;
                insert_func(fe);
            }
        }
    }
    closedir(dir);
}

static void free_func_table(){
    for(int i=0;i<FUNC_HASH_SIZE;i++){
        FuncEntry* e=func_hash[i];
        while(e){
            FuncEntry* tmp=e;
            e=e->next;
            free(tmp->name);
            if(tmp->buf && tmp->len>0) munmap(tmp->buf,tmp->len);
            free(tmp);
        }
        func_hash[i]=NULL;
    }
}

// ---------------- Precompiled IR ----------------
typedef struct IRStmt{
    int lhs_index;
    varfunc_t func_ptr;
    int arg_indices[MAX_ARGS];
    int argc;
} IRStmt;

typedef struct IR{
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

static void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }
static void ir_add(IR* ir, IRStmt s){
    if(ir->count>=ir->capacity){
        ir->capacity=ir->capacity?ir->capacity*2:8;
        ir->stmts=realloc(ir->stmts,sizeof(IRStmt)*ir->capacity);
    }
    ir->stmts[ir->count++]=s;
}
static void ir_free(IR* ir){ free(ir->stmts); }

// ---------------- Load Precompiled IR File ----------------
static void load_oir(const char* path, IR* ir){
    FILE* f=fopen(path,"rb"); if(!f){ perror(path); exit(1); }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    int stmt_count=len/sizeof(IRStmt);
    ir->stmts=malloc(sizeof(IRStmt)*stmt_count); ir->count=stmt_count; ir->capacity=stmt_count;
    if(fread(ir->stmts,sizeof(IRStmt),stmt_count,f)!=stmt_count){ fclose(f); perror("read IR"); exit(1); }
    fclose(f);
}

// ---------------- Execute ----------------
static Var* argv_pool[MAX_VARS];
static void execute_ir(IRStmt* s){
    for(int i=0;i<s->argc;i++) argv_pool[i]=env_array[s->arg_indices[i]];
    Var* res=s->func_ptr(argv_pool,s->argc);
    env_array[s->lhs_index]=res; // variable reassignment preserved
}

// ---------------- Main ----------------
int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s program.oir\n",argv[0]); return 1; }

    pool_init();
    preload_binfuncs("binfuncs");

    IR ir; ir_init(&ir);
    load_oir(argv[1],&ir);

    for(int i=0;i<ir.count;i++) execute_ir(&ir.stmts[i]);

    pool_reset();
    ir_free(&ir);
    free_func_table();
    return 0;
}
