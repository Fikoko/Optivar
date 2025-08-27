// orchestrator.c
// Optivar interpreter (x64) with binary function caching
// Syntax: y = f(x1, x2, ...);
// Comments: -- anything

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <unistd.h>

typedef enum { TYPE_OBJ } VarType;

typedef struct Var {
    VarType type;
    void* data;
} Var;

typedef struct {
    char* name;
    Var* value;
} EnvEntry;

typedef struct {
    EnvEntry* entries;
    int count;
    int capacity;
} Env;

typedef Var* (*varfunc_t)(Var** args, int count);

typedef struct FuncCacheEntry {
    char* name;
    varfunc_t func;
} FuncCache;

static FuncCache* func_cache = NULL;
static int func_cache_count = 0;
static int func_cache_capacity = 0;

// --- Environment functions ---
static void env_init(Env* e){
    e->entries = NULL;
    e->count = e->capacity = 0;
}

static Var* env_get(Env* e, const char* name){
    for(int i=0;i<e->count;i++)
        if(strcmp(e->entries[i].name,name)==0) return e->entries[i].value;
    return NULL;
}

static void env_set(Env* e, const char* name, Var* val){
    for(int i=0;i<e->count;i++){
        if(strcmp(e->entries[i].name,name,name)==0){
            free(e->entries[i].name);
            e->entries[i].name = strdup(name);
            e->entries[i].value = val;
            return;
        }
    }
    if(e->count>=e->capacity){
        e->capacity = e->capacity ? e->capacity*2 : 8;
        e->entries = realloc(e->entries,e->capacity*sizeof(EnvEntry));
    }
    e->entries[e->count].name = strdup(name);
    e->entries[e->count].value = val;
    e->count++;
}

// --- Load function binary with caching ---
static varfunc_t load_func(const char* name){
    // Check cache first
    for(int i=0;i<func_cache_count;i++){
        if(strcmp(func_cache[i].name,name)==0) return func_cache[i].func;
    }

    // Build path dynamically
    size_t path_len = strlen("binfuncs/") + strlen(name) + strlen(".bin") + 1;
    char* path = malloc(path_len);
    if(!path) return NULL;
    sprintf(path,"binfuncs/%s.bin",name);

    FILE* f = fopen(path,"rb");
    free(path);
    if(!f) return NULL;

    fseek(f,0,SEEK_END);
    long len = ftell(f);
    fseek(f,0,SEEK_SET);

    void* buf = mmap(NULL,len,PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(!buf){ fclose(f); return NULL; }

    fread(buf,1,len,f);
    fclose(f);

    // Cache it
    if(func_cache_count >= func_cache_capacity){
        func_cache_capacity = func_cache_capacity ? func_cache_capacity*2 : 8;
        func_cache = realloc(func_cache, func_cache_capacity * sizeof(FuncCache));
    }
    func_cache[func_cache_count].name = strdup(name);
    func_cache[func_cache_count].func = (varfunc_t)buf;
    func_cache_count++;

    return (varfunc_t)buf;
}

// --- Execute a single statement ---
static void execute_statement(Env* env, char* stmt){
    char* comment = strstr(stmt,"--");
    if(comment) *comment='\0';

    char* start = stmt;
    while(isspace(*start)) start++;
    if(*start=='\0') return;

    char* eq = strchr(start,'=');
    if(!eq) return;
    *eq='\0';
    char* lhs = start;
    char* rhs = eq+1;
    while(isspace(*lhs)) lhs++;
    while(isspace(*rhs)) rhs++;

    char* varname = strdup(lhs);
    if(!varname) return;

    char* paren = strchr(rhs,'(');
    if(!paren) { free(varname); return; }
    *paren='\0';
    char* funcname = strdup(rhs);
    if(!funcname) { free(varname); return; }
    while(isspace(*funcname)) funcname++;

    char* args_str = paren+1;
    char* close = strrchr(args_str,')');
    if(!close) { free(varname); free(funcname); return; }
    *close='\0';

    int argc=0, capacity=4;
    Var** argv = malloc(capacity*sizeof(Var*));
    if(!argv){ free(varname); free(funcname); return; }

    char* token = strtok(args_str,",");
    while(token){
        while(isspace(*token)) token++;
        if(*token=='\0'){ token=strtok(NULL,","); continue; }

        Var* v = env_get(env, token);
        if(!v){
            v = malloc(sizeof(Var));
            if(!v){ token=strtok(NULL,","); continue; }
            v->type = TYPE_OBJ;
            v->data = strdup(token);
        }
        argv[argc++] = v;
        if(argc >= capacity){
            capacity *= 2;
            argv = realloc(argv, capacity*sizeof(Var*));
        }
        token = strtok(NULL,",");
    }

    varfunc_t f = load_func(funcname);
    if(!f){
        printf("Error: function %s not found\n", funcname);
        for(int i=0;i<argc;i++){ if(argv[i]->data) free(argv[i]->data); free(argv[i]); }
        free(argv); free(varname); free(funcname); return;
    }

    Var* res = f(argv,argc);
    env_set(env,varname,res);

    for(int i=0;i<argc;i++){ if(argv[i]->data) free(argv[i]->data); free(argv[i]); }
    free(argv); free(varname); free(funcname);
}

// --- Main ---
int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s file.optivar\n",argv[0]); return 1; }

    Env env;
    env_init(&env);

    FILE* f = fopen(argv[1],"r");
    if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END);
    long len = ftell(f);
    fseek(f,0,SEEK_SET);
    char* buf = malloc(len+1);
    fread(buf,1,len,f);
    fclose(f);
    buf[len]='\0';

    char* stmt = strtok(buf,";");
    while(stmt){
        execute_statement(&env,stmt);
        stmt = strtok(NULL,";");
    }

    free(buf);
    return 0;
}
