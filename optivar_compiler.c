// optivar_compiler.c
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
#define VAR_CHUNK_SIZE 1024
#define FIXED_ARG_POOL 64
#define INLINE_THRESHOLD 3
#define MAX_NAME_LEN 128
#define VAR_TABLE_SIZE 2048

// -------------------- VarSlot & Pools --------------------
typedef struct VarSlot {
    void* data;            // name or user data
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

static VarSlot** env_array = NULL;   // pointers to VarSlot
static int var_count = 0;
static int env_alloc_size = 0;

static VarSlot* var_table[VAR_TABLE_SIZE]; // hash table -> VarSlot*

static unsigned int hash_name(const char* s){
    unsigned int h = 0;
    while(*s) h = (h * 31) + (unsigned char)(*s++);
    return h % VAR_TABLE_SIZE;
}

static VarSlot* pool_alloc(){
    // try fixed pool first
    for(int i=0;i<fixed_top;i++){
        if(!fixed_pool[i].in_use){
            fixed_pool[i].in_use = 1;
            fixed_pool[i].last_use = -1;
            fixed_pool[i].constant = 0;
            pthread_mutex_init(&fixed_pool[i].lock, NULL);
            return &fixed_pool[i];
        }
    }
    if(fixed_top < FIXED_VARS){
        VarSlot* slot = &fixed_pool[fixed_top++];
        slot->in_use = 1; slot->last_use = -1; slot->constant = 0;
        pthread_mutex_init(&slot->lock, NULL);
        return slot;
    }
    // search dynamic chunks
    VarPoolChunk* chunk = dynamic_pool;
    while(chunk){
        for(int i=0;i<chunk->capacity;i++){
            if(!chunk->slots[i].in_use){
                chunk->slots[i].in_use = 1;
                chunk->slots[i].last_use = -1;
                chunk->slots[i].constant = 0;
                pthread_mutex_init(&chunk->slots[i].lock, NULL);
                return &chunk->slots[i];
            }
        }
        chunk = chunk->next;
    }
    // allocate new chunk
    VarPoolChunk* new_chunk = malloc(sizeof(VarPoolChunk));
    if(!new_chunk){ perror("malloc VarPoolChunk"); exit(EXIT_FAILURE); }
    new_chunk->slots = calloc(VAR_CHUNK_SIZE, sizeof(VarSlot));
    if(!new_chunk->slots){ perror("calloc VarPoolChunk->slots"); exit(EXIT_FAILURE); }
    new_chunk->capacity = VAR_CHUNK_SIZE;
    new_chunk->next = dynamic_pool;
    dynamic_pool = new_chunk;
    for(int i=0;i<new_chunk->capacity;i++) pthread_mutex_init(&new_chunk->slots[i].lock, NULL);
    new_chunk->slots[0].in_use = 1;
    new_chunk->slots[0].last_use = -1;
    new_chunk->slots[0].constant = 0;
    return &new_chunk->slots[0];
}

// -------------------- Function table (.bin loader) --------------------
typedef struct {
    char name[MAX_NAME_LEN];
    void* ptr;     // pointer into func_blob
    size_t len;
    size_t offset;
} FuncEntry;

static FuncEntry func_table[256];
static int func_count = 0;
static char* func_blob = NULL;
static size_t func_blob_size = 0;

static void preload_binfuncs(const char* dirpath){
    DIR* dir = opendir(dirpath);
    if(!dir){ perror("opendir"); return; }
    struct dirent* entry;
    size_t total_size = 0;

    // first pass: sum sizes
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

    func_blob = mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
            strncpy(funcname, entry->d_name, len - 4);
            funcname[len - 4] = '\0';
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);
            FILE* f = fopen(path, "rb");
            if(!f){ perror(path); continue; }
            if(fseek(f, 0, SEEK_END) != 0){ perror("fseek"); fclose(f); continue; }
            long flen = ftell(f);
            if(flen < 0){ perror("ftell"); fclose(f); continue; }
            rewind(f);
            if((size_t)flen + offset > func_blob_size){ fprintf(stderr, "bin files exceed sum size\n"); fclose(f); break; }
            size_t got = fread(func_blob + offset, 1, (size_t)flen, f);
            if(got != (size_t)flen){ perror("fread"); fclose(f); exit(EXIT_FAILURE); }
            fclose(f);
            if(func_count >= (int)(sizeof(func_table)/sizeof(func_table[0]))){
                fprintf(stderr, "too many .bin functions, skipping %s\n", funcname);
                break;
            }
            strncpy(func_table[func_count].name, funcname, MAX_NAME_LEN-1);
            func_table[func_count].name[MAX_NAME_LEN-1] = '\0';
            func_table[func_count].ptr = (void*)(func_blob + offset);
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
    func_blob = NULL;
    func_blob_size = 0;
    func_count = 0;
}

// -------------------- IR structures & ArgBlocks --------------------
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

static void ir_init(IR* ir){
    ir->stmts = NULL;
    ir->count = ir->capacity = 0;
}

static IRStmt* ir_alloc_stmt(IR* ir){
    if(ir->count >= ir->capacity){
        int newcap = ir->capacity ? ir->capacity * 2 : 8;
        IRStmt* tmp = realloc(ir->stmts, sizeof(IRStmt) * newcap);
        if(!tmp){ perror("realloc IR"); exit(EXIT_FAILURE); }
        ir->stmts = tmp;
        ir->capacity = newcap;
    }
    // zero-initialize new statement slot
    IRStmt* s = &ir->stmts[ir->count++];
    memset(s, 0, sizeof(IRStmt));
    return s;
}

typedef struct ArgBlock {
    int* args;
    int capacity;
    int used;
    struct ArgBlock* next;
} ArgBlock;

static ArgBlock* arg_blocks = NULL;

// returns pointer to contiguous space for n ints; reused until freed by free_arg_blocks()
static int* arg_alloc(int n){
    ArgBlock* b = arg_blocks;
    while(b){
        if(b->capacity - b->used >= n){
            int* ptr = b->args + b->used;
            b->used += n;
            return ptr;
        }
        b = b->next;
    }
    // new block: allocate at least FIXED_ARG_POOL or n
    int cap = (n > FIXED_ARG_POOL) ? n : FIXED_ARG_POOL;
    ArgBlock* nb = malloc(sizeof(ArgBlock));
    if(!nb){ perror("malloc ArgBlock"); exit(EXIT_FAILURE); }
    nb->args = malloc(sizeof(int) * cap);
    if(!nb->args){ perror("malloc ArgBlock->args"); exit(EXIT_FAILURE); }
    nb->capacity = cap;
    nb->used = n;
    nb->next = arg_blocks;
    arg_blocks = nb;
    return nb->args;
}

static void free_arg_blocks(){
    ArgBlock* b = arg_blocks;
    while(b){
        ArgBlock* nx = b->next;
        free(b->args);
        free(b);
        b = nx;
    }
    arg_blocks = NULL;
}

// -------------------- Parsing & optimizations --------------------
static int var_index(const char* name){
    unsigned int h = hash_name(name);
    for(int i=0;i<VAR_TABLE_SIZE;i++){
        unsigned int idx = (h + i) % VAR_TABLE_SIZE;
        if(!var_table[idx]){
            VarSlot* slot = pool_alloc();
            slot->data = strdup(name);
            if(!slot->data){ perror("strdup"); exit(EXIT_FAILURE); }
            var_table[idx] = slot;
            if(var_count >= env_alloc_size){
                int new_size = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
                VarSlot** new_env = realloc(env_array, sizeof(VarSlot*) * new_size);
                if(!new_env){ perror("realloc env_array"); exit(EXIT_FAILURE); }
                env_array = new_env;
                env_alloc_size = new_size;
            }
            env_array[var_count] = slot;
            return var_count++;
        }
        if(strcmp((char*)var_table[idx]->data, name) == 0){
            // find its index in env_array
            for(int j=0;j<var_count;j++) if(env_array[j] == var_table[idx]) return j;
        }
    }
    return -1;
}

static IRStmt parse_statement(char* stmt){
    IRStmt s;
    memset(&s, 0, sizeof(s));
    char* comment = strstr(stmt, "--");
    if(comment) *comment = '\0';
    while(isspace((unsigned char)*stmt)) stmt++;
    if(*stmt == '\0') return s;
    char* eq = strchr(stmt, '=');
    if(!eq) return s;
    *eq = '\0';
    // left side variable (trim)
    char* lhs = stmt;
    while(isspace((unsigned char)*lhs)) lhs++;
    char* lhs_end = lhs + strlen(lhs) - 1;
    while(lhs_end > lhs && isspace((unsigned char)*lhs_end)) { *lhs_end = '\0'; lhs_end--; }
    s.lhs_index = var_index(lhs);
    char* rhs = eq + 1;
    while(isspace((unsigned char)*rhs)) rhs++;
    char* paren = strchr(rhs, '(');
    if(!paren) return s;
    *paren = '\0';
    // find function
    char* funcname = rhs;
    char* fend = funcname + strlen(funcname) - 1;
    while(fend > funcname && isspace((unsigned char)*fend)) { *fend = '\0'; fend--; }
    for(int i=0;i<func_count;i++){
        if(strcmp(func_table[i].name, funcname) == 0){
            s.func_ptr = func_table[i].ptr;
            if(func_table[i].len <= INLINE_THRESHOLD) s.inlined = 1;
            break;
        }
    }
    char* args_str = paren + 1;
    char* close = strrchr(args_str, ')');
    if(!close) return s;
    *close = '\0';
    int arg_cap = 16;
    s.arg_indices = arg_alloc(arg_cap);
    s.argc = 0;
    char* p = args_str;
    while(*p){
        while(isspace((unsigned char)*p)) p++;
        if(*p == ',' ) { p++; continue; }
        char* start = p;
        while(*p && *p != ',' && *p != ')') p++;
        // trim end spaces
        char* end = p - 1;
        while(end > start && isspace((unsigned char)*end)) { *end = '\0'; end--; }
        if(p > start){
            if(s.argc >= arg_cap){
                // allocate new buffer of larger capacity via arg_alloc (safe)
                arg_cap *= 2;
                int* new_args = arg_alloc(arg_cap);
                if(!new_args){ perror("arg_alloc for expand"); exit(EXIT_FAILURE); }
                memcpy(new_args, s.arg_indices, sizeof(int) * s.argc);
                s.arg_indices = new_args;
            }
            // allow variable names with surrounding spaces
            char tmp[256];
            int len = (int)(end - start + 1);
            if(len >= (int)sizeof(tmp)) len = (int)sizeof(tmp) - 1;
            memcpy(tmp, start, (size_t)len); tmp[len] = '\0';
            // trim leading spaces
            char* t = tmp; while(isspace((unsigned char)*t)) t++;
            int idx = var_index(t);
            s.arg_indices[s.argc++] = idx;
        }
        if(*p == ',') p++;
    }
    return s;
}

static void constant_folding(IR* ir){
    for(int i=0;i<ir->count;i++){
        IRStmt* s = &ir->stmts[i];
        if(s->dead) continue;
        if(!s->func_ptr) continue;
        int all_const = 1;
        long val = 0;
        for(int j=0;j<s->argc;j++){
            int ai = s->arg_indices[j];
            if(ai < 0 || ai >= var_count){ all_const = 0; break; }
            VarSlot* arg = env_array[ai];
            if(!arg->constant){ all_const = 0; break; }
            val += arg->value;
        }
        if(all_const){
            VarSlot* lhs = env_array[s->lhs_index];
            lhs->constant = 1;
            lhs->value = val;
            // mark stmt as having no runtime function (folded)
            s->func_ptr = NULL;
        }
    }
}

static void dead_code_elimination(IR* ir){
    if(var_count == 0) return;
    int *used = calloc(var_count, sizeof(int));
    if(!used){ perror("calloc used"); exit(EXIT_FAILURE); }
    for(int i=ir->count-1;i>=0;i--){
        IRStmt* s = &ir->stmts[i];
        if(!s->func_ptr){ continue; }
        if(!used[s->lhs_index]) s->dead = 1;
        for(int j=0;j<s->argc;j++) used[s->arg_indices[j]] = 1;
    }
    free(used);
}

static void ir_batching(IR* ir){
    for(int i=0;i<ir->count-1;i++){
        IRStmt* s = &ir->stmts[i];
        if(s->dead || !s->func_ptr) continue;
        IRStmt* next = &ir->stmts[i+1];
        if(next->dead || !next->func_ptr) continue;
        if(s->func_ptr == next->func_ptr){
            int total = s->argc + next->argc;
            int* merged = arg_alloc(total);
            memcpy(merged, s->arg_indices, sizeof(int) * s->argc);
            memcpy(merged + s->argc, next->arg_indices, sizeof(int) * next->argc);
            s->arg_indices = merged;
            s->argc = total;
            next->dead = 1;
        }
    }
}

static void build_dependencies(IR* ir){
    for(int i=0;i<ir->count;i++){
        IRStmt* s = &ir->stmts[i];
        s->dep_count = 0;
        s->dep_indices = NULL;
        s->executed = 0;
        int dep_cap = 4;
        int *deps = malloc(sizeof(int) * dep_cap);
        if(!deps && dep_cap>0){ perror("malloc deps"); exit(EXIT_FAILURE); }
        int deps_used = 0;
        for(int j=0;j<i;j++){
            IRStmt* prev = &ir->stmts[j];
            for(int k=0;k<s->argc;k++){
                if(prev->lhs_index == s->arg_indices[k]){
                    if(deps_used >= dep_cap){
                        dep_cap *= 2;
                        int *tmp = realloc(deps, sizeof(int) * dep_cap);
                        if(!tmp){ perror("realloc deps"); exit(EXIT_FAILURE); }
                        deps = tmp;
                    }
                    deps[deps_used++] = j;
                    break;
                }
            }
        }
        if(deps_used == 0){
            free(deps);
            s->dep_indices = NULL;
            s->dep_count = 0;
        } else {
            s->dep_indices = deps;
            s->dep_count = deps_used;
        }
    }
}

// -------------------- Environment setup & cleanup --------------------
static void init_env(int total_vars){
    env_alloc_size = total_vars > 0 ? total_vars : (FIXED_VARS*2);
    env_array = malloc(sizeof(VarSlot*) * env_alloc_size);
    if(!env_array){ perror("malloc env_array"); exit(EXIT_FAILURE); }
    // preallocate VarSlot objects that serve as placeholders (not from fixed_pool)
    for(int i=0;i<env_alloc_size;i++){
        env_array[i] = malloc(sizeof(VarSlot));
        if(!env_array[i]){ perror("malloc env_array[i]"); exit(EXIT_FAILURE); }
        env_array[i]->data = NULL;
        env_array[i]->in_use = 0;
        env_array[i]->last_use = -1;
        env_array[i]->constant = 0;
        env_array[i]->value = 0;
        pthread_mutex_init(&env_array[i]->lock, NULL);
    }
    var_count = 0;
}

static void free_env(){
    // free only entries that were used (var_count)
    for(int i=0;i<var_count;i++){
        if(env_array[i]->data) free(env_array[i]->data);
        pthread_mutex_destroy(&env_array[i]->lock);
        free(env_array[i]);
    }
    // free any additional placeholders we preallocated
    for(int i=var_count;i<env_alloc_size;i++){
        if(env_array[i]){ pthread_mutex_destroy(&env_array[i]->lock); free(env_array[i]); }
    }
    free(env_array);
    env_array = NULL;
    env_alloc_size = 0;
    var_count = 0;
    // free fixed pool locks? Not necessary: those are not individually destroyed; but we'll avoid double destroying.
}

// -------------------- External executor (binary) --------------------
extern void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads);

// -------------------- Main --------------------
int main(int argc, char** argv){
    if(argc < 3){
        fprintf(stderr, "Usage: %s input.optivar binfuncs_dir\n", argv[0]);
        return 1;
    }

    // init environment with a reasonable starting capacity
    init_env(FIXED_VARS * 2);

    // preload .bin functions (including executor.bin)
    preload_binfuncs(argv[2]);

    // Read input .optivar file
    FILE* f = fopen(argv[1], "r");
    if(!f){ perror("fopen input"); return 1; }
    if(fseek(f, 0, SEEK_END) != 0){ perror("fseek"); fclose(f); return 1; }
    long len = ftell(f);
    if(len < 0){ perror("ftell"); fclose(f); return 1; }
    rewind(f);
    char* buf = malloc((size_t)len + 1);
    if(!buf){ perror("malloc buf"); fclose(f); return 1; }
    if(fread(buf, 1, (size_t)len, f) != (size_t)len){ perror("fread"); free(buf); fclose(f); return 1; }
    fclose(f);
    buf[len] = '\0';

    IR ir; ir_init(&ir);

    // parse statements separated by ';'
    char* saveptr = NULL;
    char* tok = strtok_r(buf, ";", &saveptr);
    int stmt_index = 0;
    while(tok){
        IRStmt s = parse_statement(tok);
        // update last_use for args
        for(int i=0;i<s.argc;i++){
            int ai = s.arg_indices[i];
            if(ai >= 0 && ai < var_count){
                VarSlot* slot = env_array[ai];
                if(slot->last_use < stmt_index) slot->last_use = stmt_index;
            }
        }
        IRStmt* dst = ir_alloc_stmt(&ir);
        *dst = s; // copy struct (note: arg_indices points into arg_blocks)
        tok = strtok_r(NULL, ";", &saveptr);
        stmt_index++;
    }
    free(buf);

    // run optimizations
    constant_folding(&ir);
    dead_code_elimination(&ir);
    ir_batching(&ir);
    build_dependencies(&ir);

    // find executor func by name "executor" (preferred), otherwise first function
    void (*bin_exec)(IRStmt*, int, VarSlot**, int) = NULL;
    for(int i=0;i<func_count;i++){
        if(strcmp(func_table[i].name, "executor") == 0){
            bin_exec = func_table[i].ptr;
            break;
        }
    }
    if(!bin_exec && func_count > 0){
        bin_exec = func_table[0].ptr; // fallback
    }

    // If we have a dynamic executor in .bin, call it; otherwise call local external if linked
    if(bin_exec){
        // If executor.bin was compiled as a shared blob, calling its function pointer directly is possible.
        // Ensure the function signature matches: void executor(IRStmt*, int, VarSlot**, int)
        bin_exec(ir.stmts, ir.count, env_array, 8);
    } else {
        // fall back to linked executor if present
        // Note: If you compiled the separate executor and linked it into this binary, it will be used.
        // Otherwise nothing to do.
        #ifdef HAVE_LINKED_EXECUTOR
        executor(ir.stmts, ir.count, env_array, 8);
        #else
        fprintf(stderr, "No executor found in %s and no linked executor available.\n", argv[2]);
        #endif
    }

    // print final variable values
    for(int i=0;i<var_count;i++){
        printf("Var %d = %ld\n", i, env_array[i]->value);
    }

    // cleanup: free dep_indices arrays
    for(int i=0;i<ir.count;i++){
        if(ir.stmts[i].dep_indices) free(ir.stmts[i].dep_indices);
        // arg_indices were allocated in ArgBlock pool; freed by free_arg_blocks
    }

    free_env();
    free_func_table();
    free(ir.stmts);
    free_arg_blocks();

    return 0;
}
