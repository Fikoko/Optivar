// orchestrator.c - 
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

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
    if(var_pool.top < POOL_SIZE) return &var_pool.pool[var_pool.top++];
    return malloc(sizeof(Var));
}
static void pool_reset() { var_pool.top = 0; }

// ---------------- Hash Table Environment ----------------
typedef struct EnvEntry {
    char* name;
    Var* value;
    struct EnvEntry* next;
} EnvEntry;

#define ENV_BUCKETS 1024
typedef struct {
    EnvEntry* buckets[ENV_BUCKETS];
} Env;

static unsigned long hash(const char* str){
    unsigned long h = 5381;
    while(*str) h = ((h << 5) + h) + (unsigned char)(*str++);
    return h % ENV_BUCKETS;
}

static void env_init(Env* e){ memset(e->buckets, 0, sizeof(e->buckets)); }

static Var* env_get(Env* e, const char* name){
    unsigned long h = hash(name);
    EnvEntry* cur = e->buckets[h];
    while(cur){
        if(strcmp(cur->name,name)==0) return cur->value;
        cur = cur->next;
    }
    return NULL;
}

static void env_set(Env* e, const char* name, Var* val){
    unsigned long h = hash(name);
    EnvEntry* cur = e->buckets[h];
    while(cur){
        if(strcmp(cur->name,name)==0){ cur->value=val; return; }
        cur = cur->next;
    }
    EnvEntry* ne = malloc(sizeof(EnvEntry));
    ne->name = strdup(name); ne->value = val;
    ne->next = e->buckets[h]; e->buckets[h] = ne;
}

static void env_free(Env* e){
    for(int i=0;i<ENV_BUCKETS;i++){
        EnvEntry* cur = e->buckets[i];
        while(cur){
            EnvEntry* next = cur->next;
            free(cur->name);
            free(cur);
            cur = next;
        }
    }
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

    // Store in cache
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

// ---------------- Intermediate Representation ----------------
typedef struct IRStmt {
    char* lhs;
    char* funcname;
    char** arg_tokens;
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
        free(ir->stmts[i].lhs);
        free(ir->stmts[i].funcname);
        for(int j=0;j<ir->stmts[i].argc;j++)
            free(ir->stmts[i].arg_tokens[j]);
        free(ir->stmts[i].arg_tokens);
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
    s.lhs = strdup(stmt); while(isspace(*s.lhs)) s.lhs++;
    char* rhs = eq+1; while(isspace(*rhs)) rhs++;
    char* paren = strchr(rhs,'('); if(!paren) return s;
    *paren='\0';
    s.funcname = strdup(rhs); while(isspace(*s.funcname)) s.funcname++;
    char* args_str = paren+1;
    char* close = strrchr(args_str,')'); if(!close) return s;
    *close='\0';

    s.arg_tokens=NULL; s.argc=0; int cap=4;
    s.arg_tokens = malloc(sizeof(char*)*cap);
    char* token = strtok(args_str,",");
    while(token){
        while(isspace(*token)) token++;
        if(*token=='\0'){ token=strtok(NULL,","); continue; }
        if(s.argc>=cap){ cap*=2; s.arg_tokens=realloc(s.arg_tokens,sizeof(char*)*cap); }
        s.arg_tokens[s.argc++] = strdup(token);
        token=strtok(NULL,",");
    }
    return s;
}

// ---------------- Execute IR Statement ----------------
static void execute_ir(IRStmt* s, Env* env){
    if(!s->lhs || !s->funcname) return;

    int argc = s->argc; Var** argv = malloc(sizeof(Var*)*argc);
    for(int i=0;i<argc;i++){
        Var* v = env_get(env,s->arg_tokens[i]);
        if(!v){
            v = pool_alloc(); v->type=TYPE_OBJ;
            v->data = strdup(s->arg_tokens[i]);
        }
        argv[i]=v;
    }

    varfunc_t f = load_func(s->funcname);
    if(!f){ printf("Error: %s not found\n", s->funcname); free(argv); return; }

    Var* res = f(argv,argc);
    env_set(env,s->lhs,res);
    free(argv);
}

// ---------------- Main ----------------
int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s file.optivar\n",argv[0]); return 1; }

    Env env; env_init(&env);
    pool_init();

    FILE* f = fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len = ftell(f); fseek(f,0,SEEK_SET);
    char* buf = malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt = strtok(buf,";");
    while(stmt){ ir_add(&ir, parse_statement(stmt)); stmt=strtok(NULL,";"); }
    free(buf);

    for(int i=0;i<ir.count;i++){
        execute_ir(&ir.stmts[i],&env);
        pool_reset();
    }

    ir_free(&ir);
    env_free(&env);
    free_func_cache();

    return 0;
}
