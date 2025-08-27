// orchestrator_optimized.c - High-performance Optivar interpreter
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_VARS 1024
#define MAX_ARGS 8

// ---------------- Types ----------------
typedef enum { TYPE_OBJ } VarType;

typedef struct Var {
    VarType type;
    void* data;
} Var;

// ---------------- Object Pool ----------------
#define POOL_SIZE 1024
typedef struct {
    Var pool[POOL_SIZE];
    int top;
} VarPool;

static VarPool var_pool;
static void pool_init() { var_pool.top = 0; }
static Var* pool_alloc() {
    if (var_pool.top < POOL_SIZE) return &var_pool.pool[var_pool.top++];
    return malloc(sizeof(Var));
}
static void pool_reset() { var_pool.top = 0; }

// ---------------- Environment ----------------
static Var* env_array[MAX_VARS];
static int var_count = 0;

// Map variable name to index
static int var_index(const char* name) {
    for (int i = 0; i < var_count; i++)
        if (env_array[i] && env_array[i]->data && strcmp((char*)env_array[i]->data, name) == 0)
            return i;

    if (var_count >= MAX_VARS) { fprintf(stderr, "Too many variables\n"); exit(1); }
    Var* v = pool_alloc();
    v->type = TYPE_OBJ;
    v->data = strdup(name);
    env_array[var_count] = v;
    return var_count++;
}

// ---------------- Binary Function Caching ----------------
typedef Var* (*varfunc_t)(Var** args,int argc);

typedef struct FuncCacheEntry {
    char* name;
    varfunc_t func;
    void* buf;
    size_t len;
} FuncCache;

static FuncCache* func_cache = NULL;
static int func_cache_count = 0;
static int func_cache_capacity = 0;

static varfunc_t load_func(const char* name){
    for(int i=0;i<func_cache_count;i++)
        if(strcmp(func_cache[i].name,name)==0) return func_cache[i].func;

    // Load binary
    char path[256];
    snprintf(path,sizeof(path),"binfuncs/%s.bin",name);
    FILE* f = fopen(path,"rb");
    if(!f) return NULL;
    fseek(f,0,SEEK_END); long len = ftell(f); fseek(f,0,SEEK_SET);
    void* buf = mmap(NULL,len,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(!buf){ fclose(f); return NULL; }
    if(fread(buf,1,len,f)!=len){ fclose(f); munmap(buf,len); return NULL; }
    fclose(f);

    if(func_cache_count>=func_cache_capacity){
        func_cache_capacity = func_cache_capacity ? func_cache_capacity*2:8;
        func_cache = realloc(func_cache,sizeof(FuncCache)*func_cache_capacity);
    }
    func_cache[func_cache_count].name = strdup(name);
    func_cache[func_cache_count].func = (varfunc_t)buf;
    func_cache[func_cache_count].buf = buf;
    func_cache[func_cache_count].len = len;
    func_cache_count++;
    return (varfunc_t)buf;
}

static void free_func_cache(){
    for(int i=0;i<func_cache_count;i++){
        free(func_cache[i].name);
        if(func_cache[i].buf && func_cache[i].len>0)
            munmap(func_cache[i].buf,func_cache[i].len);
    }
    free(func_cache);
}

// ---------------- IR ----------------
typedef struct IRStmt {
    int lhs_index;
    char* funcname;
    int* arg_indices;
    int argc;
} IRStmt;

typedef struct IR {
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

static void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }
static void ir_add(IR* ir, IRStmt s){
    if(ir->count>=ir->capacity){
        ir->capacity = ir->capacity ? ir->capacity*2:8;
        ir->stmts = realloc(ir->stmts,sizeof(IRStmt)*ir->capacity);
    }
    ir->stmts[ir->count++] = s;
}

static void ir_free(IR* ir){
    for(int i=0;i<ir->count;i++){
        free(ir->stmts[i].funcname);
        free(ir->stmts[i].arg_indices);
    }
    free(ir->stmts);
}

// ---------------- Parsing ----------------
static IRStmt parse_statement(char* stmt){
    IRStmt s = {0};
    char* comment = strstr(stmt,"--"); if(comment)*comment='\0';
    while(isspace(*stmt)) stmt++;
    if(*stmt=='\0') return s;

    char* eq = strchr(stmt,'='); if(!eq) return s;
    *eq='\0';
    s.lhs_index = var_index(stmt);
    char* rhs = eq+1; while(isspace(*rhs)) rhs++;
    char* paren = strchr(rhs,'('); if(!paren) return s;
    *paren='\0';
    s.funcname = strdup(rhs); while(isspace(*s.funcname)) s.funcname++;
    char* args_str = paren+1;
    char* close = strrchr(args_str,')'); if(!close) return s;
    *close='\0';

    int cap = 4; s.arg_indices = malloc(sizeof(int)*cap); s.argc=0;
    char* token = strtok(args_str,",");
    while(token){
        while(isspace(*token)) token++;
        if(*token=='\0'){ token=strtok(NULL,","); continue; }
        if(s.argc>=cap){ cap*=2; s.arg_indices=realloc(s.arg_indices,sizeof(int)*cap); }
        s.arg_indices[s.argc++] = var_index(token);
        token=strtok(NULL,",");
    }
    return s;
}

// ---------------- Execute IR Statement ----------------
static void execute_ir(IRStmt* s){
    if(!s->funcname) return;

    Var* argv[MAX_ARGS];
    Var** argv_extra = NULL;

    if(s->argc <= MAX_ARGS){
        for(int i=0;i<s->argc;i++)
            argv[i] = env_array[s->arg_indices[i]];
    } else {
        argv_extra = malloc(sizeof(Var*)*s->argc);
        for(int i=0;i<s->argc;i++)
            argv_extra[i] = env_array[s->arg_indices[i]];
    }

    varfunc_t f = load_func(s->funcname);
    if(!f){ printf("Error: %s not found\n", s->funcname); if(argv_extra) free(argv_extra); return; }

    Var* res = f(argv_extra ? argv_extra : argv, s->argc);
    env_array[s->lhs_index] = res;

    if(argv_extra) free(argv_extra);
}

// ---------------- Main ----------------
int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s file.optivar\n",argv[0]); return 1; }

    pool_init();

    FILE* f = fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len = ftell(f); fseek(f,0,SEEK_SET);
    char* buf = malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt = strtok(buf,";");
    while(stmt){ ir_add(&ir, parse_statement(stmt)); stmt=strtok(NULL,";"); }
    free(buf);

    for(int i=0;i<ir.count;i++){
        execute_ir(&ir.stmts[i]);
        pool_reset();
    }

    ir_free(&ir);
    free_func_cache();

    return 0;
}
