// orchestrator.c
// Optivar non-compiled interpreter (x64)
// Syntax: y = f(x1, x2, ...);
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
static Var* var_string(const char* s) { Var* v = malloc(sizeof(Var)); v->type = TYPE_STRING; v->data.s_val = strdup(s); return v; }
static Var* var_bool(int b) { Var* v = malloc(sizeof(Var)); v->type = TYPE_BOOL; v->data.b_val = b; return v; }
static Var* var_null() { Var* v = malloc(sizeof(Var)); v->type = TYPE_NULL; return v; }

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

// --- Determine type of literal ---
static Var* parse_literal(const char* token) {
    if(strcmp(token,"null")==0) return var_null();
    if(strcmp(token,"true")==0) return var_bool(1);
    if(strcmp(token,"false")==0) return var_bool(0);
    char* endptr;
    long long i = strtoll(token,&endptr,10);
    if(*endptr=='\0') return var_int(i);
    double f = strtod(token,&endptr);
    if(*endptr=='\0') return var_float(f);
    return var_string(token); // treat as string literal
}

// --- Parse and execute a single statement ---
static void execute_statement(Env* env, char* stmt) {
    // Remove comments
    char* comment = strstr(stmt,"--");
    if(comment) *comment='\0';

    // Skip empty lines
    char* start = stmt;
    while(isspace(*start)) start++;
    if(*start=='\0') return;

    // Split lhs and rhs
    char* eq = strchr(start,'=');
    if(!eq) return; // invalid
    *eq='\0';
    char* lhs = start;
    char* rhs = eq+1;
    while(isspace(*lhs)) lhs++;
    while(isspace(*rhs)) rhs++;

    // Parse function name
    char* paren = strchr(rhs,'(');
    if(!paren) return; // invalid
    *paren = '\0';
    char* funcname = rhs;
    while(isspace(*funcname)) funcname++;

    // Parse arguments string
    char* args_str = paren+1;
    char* close = strrchr(args_str,')');
    if(!close) return;
    *close='\0';

    // Dynamic argument array
    int argc = 0;
    int capacity = 4;
    Var** argv = malloc(capacity * sizeof(Var*));

    char* token = strtok(args_str,",");
    while(token){
        while(isspace(*token)) token++;
        if(*token=='\0') { token = strtok(NULL,","); continue; }

        Var* v = env_get(env, token); // try variable
        if(!v) v = parse_literal(token); // else literal
        argv[argc++] = v;

        if(argc>=capacity){
            capacity *= 2;
            argv = realloc(argv, capacity*sizeof(Var*));
        }

        token = strtok(NULL,",");
    }

    // Load function dynamically
    varfunc_t f = (varfunc_t)load_func(funcname);
    if(!f){ printf("Error: function %s not found\n", funcname); free(argv); return; }

    Var* res = f(argv,argc);
    env_set(env,lhs,res);

    free(argv);
}

int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s file.optivar\n",argv[0]); return 1; }

    Env env;
    env_init(&env);

    FILE* f = fopen(argv[1],"r");
    if(!f) { perror("fopen"); return 1; }
    fseek(f,0,SEEK_END);
    long len = ftell(f);
    fseek(f,0,SEEK_SET);
    char* buf = malloc(len+1);
    fread(buf,1,len,f); fclose(f); buf[len]='\0';

    // Split statements by ';'
    char* stmt = strtok(buf,";");
    while(stmt){
        execute_statement(&env,stmt);
        stmt = strtok(NULL,";");
    }

    free(buf);
    return 0;
}
