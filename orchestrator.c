// orchestrator_optimized_final_hash_annotated.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>

#define MAX_VARS 1024
#define HASH_SIZE 2048  // hash table size >= MAX_VARS

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

// Object pool stores all variable objects
static VarPool var_pool;

// Initialize pool
static void pool_init() { var_pool.top = 0; }

// Allocate new Var from pool
static Var* pool_alloc() {
    if (var_pool.top < POOL_SIZE) return &var_pool.pool[var_pool.top++];
    return malloc(sizeof(Var)); // fallback if pool exhausted
}

// Reset pool: all previous Vars are recycled
static void pool_reset() { var_pool.top = 0; }

// ---------------- Environment ----------------
static Var* env_array[MAX_VARS];
static int var_count = 0;

// ---------------- Hash Table for Variables ----------------
typedef struct VarEntry {
    char* name;
    int index;
    struct VarEntry* next;
} VarEntry;

static VarEntry* var_hash[HASH_SIZE];

// Simple string hash
static unsigned int hash_string(const char* s) {
    unsigned int h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)(*s++);
    return h % HASH_SIZE;
}

// Lookup or create variable
static int var_index(const char* name) {
    unsigned int h = hash_string(name);
    VarEntry* e = var_hash[h];

    // Lookup existing variable
    while (e) {
        if (strcmp(e->name, name) == 0) return e->index;
        e = e->next;
    }

    // Not found → create new variable
    if (var_count >= MAX_VARS) { fprintf(stderr, "Too many variables\n"); exit(1); }

    Var* v = pool_alloc();
    v->type = TYPE_OBJ;
    v->data = strdup(name);      // store name
    env_array[var_count] = v;

    // Insert into hash table for fast lookup
    VarEntry* new_entry = malloc(sizeof(VarEntry));
    new_entry->name = (char*)v->data; // reuse the string
    new_entry->index = var_count;
    new_entry->next = var_hash[h];
    var_hash[h] = new_entry;

    return var_count++;
}

// ---------------- Binary Function Cache ----------------
typedef Var* (*varfunc_t)(Var** args,int argc);

typedef struct FuncEntry {
    char* name;
    varfunc_t func;
    void* buf;
    size_t len;
} FuncEntry;

static FuncEntry* func_table = NULL;
static int func_table_count = 0;
static int func_table_capacity = 0;

// Preload all .bin files in binfuncs
static void preload_binfuncs(const char* dirpath) {
    DIR* dir = opendir(dirpath);
    if (!dir) { perror("opendir"); return; }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char* name = entry->d_name;
            size_t len = strlen(name);
            if (len > 4 && strcmp(name + len - 4, ".bin") == 0) {
                char funcname[256];
                strncpy(funcname, name, len - 4);
                funcname[len - 4] = '\0';

                char path[256];
                snprintf(path, sizeof(path), "%s/%s.bin", dirpath, funcname);
                FILE* f = fopen(path, "rb");
                if (!f) { perror(path); continue; }
                fseek(f, 0, SEEK_END);
                long flen = ftell(f);
                fseek(f, 0, SEEK_SET);
                void* buf = mmap(NULL, flen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (!buf) { fclose(f); perror("mmap"); continue; }
                if (fread(buf, 1, flen, f) != flen) { fclose(f); munmap(buf, flen); continue; }
                fclose(f);

                if (func_table_count >= func_table_capacity) {
                    func_table_capacity = func_table_capacity ? func_table_capacity * 2 : 8;
                    func_table = realloc(func_table, sizeof(FuncEntry) * func_table_capacity);
                }
                func_table[func_table_count].name = strdup(funcname);
                func_table[func_table_count].func = (varfunc_t)buf;
                func_table[func_table_count].buf = buf;
                func_table[func_table_count].len = flen;
                func_table_count++;
            }
        }
    }
    closedir(dir);
}

// Lookup preloaded function
static varfunc_t get_func(const char* name) {
    for (int i = 0; i < func_table_count; i++)
        if (strcmp(func_table[i].name, name) == 0)
            return func_table[i].func;
    return NULL;
}

// Free all preloaded binaries
static void free_func_table() {
    for (int i = 0; i < func_table_count; i++) {
        free(func_table[i].name);
        if (func_table[i].buf && func_table[i].len > 0)
            munmap(func_table[i].buf, func_table[i].len);
    }
    free(func_table);
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
static Var* argv_pool[MAX_VARS];  // reusable argument array

static void execute_ir(IRStmt* s){
    if(!s->funcname) return;

    // Copy arguments to preallocated pool
    for(int i=0;i<s->argc;i++)
        argv_pool[i] = env_array[s->arg_indices[i]];

    varfunc_t f = get_func(s->funcname);
    if(!f){ printf("Error: %s not found\n", s->funcname); return; }

    // ---------------- Key point: Variable reassignment ----------------
    // If lhs variable already exists, we simply overwrite the pointer.
    // No free() is called. Memory is recycled on next pool_reset().
    Var* res = f(argv_pool, s->argc);
    env_array[s->lhs_index] = res;
}

// ---------------- Main ----------------
int main(int argc,char** argv){
    if(argc<2){ printf("Usage: %s file.optivar\n",argv[0]); return 1; }

    pool_init();

    // Preload all binaries
    preload_binfuncs("binfuncs");

    FILE* f = fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len = ftell(f); fseek(f,0,SEEK_SET);
    char* buf = malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt = strtok(buf,";");
    while(stmt){ ir_add(&ir, parse_statement(stmt)); stmt=strtok(NULL,";"); }
    free(buf);

    for(int i=0;i<ir.count;i++){
        execute_ir(&ir.stmts[i]);
        // ---------------- Pool reset recycles all previously allocated Vars ----------------
        pool_reset();
    }

    ir_free(&ir);
    free_func_table();

    return 0;
}
