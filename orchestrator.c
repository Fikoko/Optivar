// orchestrator.c
// Optivar PL interpreter (x64)
// Syntax: y = f(x1, x2, ...);   // only structure
// Comments: -- anything

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef enum { TYPE_INT, TYPE_FLOAT, TYPE_STRING, TYPE_BOOL, TYPE_NULL } VarType;

typedef struct Var {
    VarType type;
    union {
        long long i_val;
        double f_val;
        char* s_val;
        int b_val;
    } data;
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

// --- Environment functions ---
static void env_init(Env* e) {
    e->entries = NULL;
    e->count = e->capacity = 0;
}

static Var* env_get(Env* e, const char* name) {
    for(int i=0;i<e->count;i++)
        if(strcmp(e->entries[i].name, name)==0) return e->entries[i].value;
    return NULL;
}

static void env_set(Env* e, const char* name, Var* val) {
    for(int i=0;i<e->count;i++) {
        if(strcmp(e->entries[i].name, name)==0) {
            free(e->entries[i].name);
            e->entries[i].name = strdup(name);
            e->entries[i].value = val;
            return;
        }
    }
    if(e->count>=e->capacity) {
        e->capacity = e->capacity ? e->capacity*2 : 8;
        e->entries = realloc(e->entries, e->capacity*sizeof(EnvEntry));
    }
    e->entries[e->count].name = strdup(name);
    e->entries[e->count].value = val;
    e->count++;
}

// --- Simple var constructors ---
static Var* var_int(long long i) { Var* v = malloc(sizeof(Var)); v->type = TYPE_INT; v->data.i_val = i; return v; }
static Var* var_float(double f) { Var* v = malloc(sizeof(Var)); v->type = TYPE_FLOAT; v->data.f_val = f; return v; }
static Var* var_null() { Var* v = malloc(sizeof(Var)); v->type = TYPE_NULL; return v; }

// --- Print Var ---
static void print_var(const Var* v) {
    if(!v) { printf("null"); return; }
    switch(v->type){
        case TYPE_INT: printf("%lld", v->data.i_val); break;
        case TYPE_FLOAT: printf("%g", v->data.f_val); break;
        case TYPE_STRING: printf("%s", v->data.s_val); break;
        case TYPE_BOOL: printf(v->data.b_val ? "true":"false"); break;
        case TYPE_NULL: printf("null"); break;
    }
}

// --- Load function binary ---
static void* load_func(const char* name) {
    char path[256];
    snprintf(path,sizeof(path),"binfuncs/%s.bin",name);
    FILE* f = fopen(path,"rb");
    if(!f) return NULL;
    fseek(f,0,SEEK_END);
    long len = ftell(f);
    fseek(f,0,SEEK_SET);
    void* buf = mmap(NULL,len,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    fread(buf,1,len,f);
    fclose(f);
    return buf;
}

// --- Parse and execute a single statement ---
static void execute_statement(Env* env, char* stmt) {
    char* comment = strstr(stmt,"--");
    if(comment) *comment='\0'; // remove comment

    char* eq = strchr(stmt,'=');
    if(!eq) return; // invalid
    *eq='\0';
    char* lhs = stmt;
    char* rhs = eq+1;
    while(isspace(*lhs)) lhs++;
    while(isspace(*rhs)) rhs++;

    // parse function call
    char* paren = strchr(rhs,'(');
    if(!paren) return;
    char funcname[64];
    int len = paren - rhs;
    strncpy(funcname,rhs,len); funcname[len]='\0';
    while(isspace(*funcname)) funcname++; 

    char* args_str = paren+1;
    char* close = strrchr(args_str,')');
    if(!close) return;
    *close='\0';

    // parse arguments
    int argc=0;
    Var* argv[16];
    char* token = strtok(args_str,",");
    while(token && argc<16){
        while(isspace(*token)) token++;
        if(strcmp(token,"null")==0) argv[argc++] = var_null();
        else argv[argc++] = var_int(atoll(token)); // for demo, all integers
        token = strtok(NULL,",");
    }

    varfunc_t f = (varfunc_t)load_func(funcname);
    if(!f){ printf("Error: function %s not found\n", funcname); return; }
    Var* res = f(argv,argc);
    env_set(env,lhs,res);

    for(int i=0;i<argc;i++) free(argv[i]);
}

int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s file.optivar\n",argv[0]); return 1; }
    Env env;
    env_init(&env);

    FILE* f = fopen(argv[1],"r");
    if(!f) { perror("fopen"); return 1; }
    fseek(f,0,SEEK_END);
    long len=ftell(f);
    fseek(f,0,SEEK_SET);
    char* buf = malloc(len+1);
    fread(buf,1,len,f); fclose(f); buf[len]='\0';

    char* stmt = strtok(buf,";\n");
    while(stmt){
        execute_statement(&env,stmt);
        stmt = strtok(NULL,";\n");
    }

    printf("Environment:\n");
    for(int i=0;i<env.count;i++){
        printf("%s = ", env.entries[i].name);
        print_var(env.entries[i].value);
        printf("\n");
    }

    free(buf);
    return 0;
}
