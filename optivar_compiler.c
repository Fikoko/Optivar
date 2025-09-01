// optivar_orchestrator.c (fully adaptive + unbounded + superoptimized)
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
#include <fcntl.h> // For open

#define MAX_IR 8192
#define FIXED_VARS 4096
#define VAR_CHUNK_SIZE 8192
#define FIXED_ARG_POOL 256
#define INLINE_THRESHOLD 3
#define MAX_NAME_LEN 128
#define CACHE_LINE 64
#define MAX_ARGS 16
#define MAX_THREADS_DEFAULT 8 // Default max threads, can be overridden

// ---------------- VarSlot ----------------
typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    char pad[CACHE_LINE - sizeof(void*) - 4*sizeof(int) - sizeof(long)];
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
    char pad[CACHE_LINE - 9*sizeof(int) - sizeof(void*) - sizeof(int*)];
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
static VarSlot** var_table = NULL;
static int var_table_size = 2048;

// ---------------- Hash function ----------------
static inline unsigned int hash_name(const char* s, int table_size){
    unsigned int h = 0;
    while(*s) h = (h * 31) + (unsigned char)(*s++);
    return h % table_size;
}

// ---------------- Arena Allocator for Temporaries ----------------
static __thread char* arena_ptr = NULL;
static __thread size_t arena_size = 0;

static void* arena_alloc(size_t size) {
    if (!arena_ptr || arena_size < size) {
        size_t new_size = size > 65536 ? size : 65536;
        arena_ptr = aligned_alloc(CACHE_LINE, new_size);
        if (!arena_ptr) { perror("aligned_alloc arena"); exit(EXIT_FAILURE); }
        arena_size = new_size;
    }
    void* ptr = arena_ptr;
    arena_ptr += size;
    arena_size -= size;
    return ptr;
}

static void arena_reset() {
    // Note: We don't free, just reset pointer for reuse in thread
    arena_ptr = NULL;
    arena_size = 0;
}

// ---------------- Pool allocator ----------------
static VarSlot* pool_alloc(){
    for(int i=0;i<fixed_top;i++){
        if(!fixed_pool[i].in_use){
            fixed_pool[i].in_use=1; fixed_pool[i].last_use=-1; fixed_pool[i].constant=0;
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
                chunk->slots[i].in_use=1; chunk->slots[i].last_use=-1; chunk->slots[i].constant=0;
                return &chunk->slots[i];
            }
        }
        chunk=chunk->next;
    }
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* new_chunk = arena_alloc(sizeof(VarPoolChunk));
    new_chunk->slots = aligned_alloc(CACHE_LINE, cap * sizeof(VarSlot));
    if(!new_chunk->slots){ perror("aligned_alloc VarPoolChunk->slots"); exit(EXIT_FAILURE);}
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
    int arg_count; // For validation
} FuncEntry;

static FuncEntry* func_table = NULL; // Dynamic array
static int func_table_size = 256;    // Initial size
static int func_count = 0;
static char* func_blob = NULL;
static size_t func_blob_size = 0;

// ---------------- Dynamic Function Table ----------------
static void grow_func_table() {
    int new_size = func_table_size * 2;
    FuncEntry* new_table = realloc(func_table, sizeof(FuncEntry) * new_size);
    if (!new_table) { perror("realloc func_table"); exit(EXIT_FAILURE); }
    memset(new_table + func_table_size, 0, sizeof(FuncEntry) * (new_size - func_table_size));
    func_table = new_table;
    func_table_size = new_size;
}

// ---------------- Lazy Load .bin functions ----------------
static void* load_binfunc(const char* name, int* arg_count_out) {
    char path[512];
    snprintf(path, sizeof(path), "./funcs/%s.bin", name); // Assume dir is ./funcs
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    void* ptr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) return NULL;
    // Assume arg_count is embedded or default to -1 (no validation)
    *arg_count_out = -1; // Placeholder; in real impl, parse from binary if needed
    return ptr;
}

static void preload_binfuncs(const char* dirpath){
    if (!func_table) {
        func_table = calloc(func_table_size, sizeof(FuncEntry));
        if (!func_table) { perror("calloc func_table"); exit(EXIT_FAILURE); }
    }
    DIR* dir = opendir(dirpath);
    if (!dir) { perror("opendir"); return; }
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcmp(entry->d_name + len - 4, ".bin") == 0) {
            if (func_count >= func_table_size) grow_func_table();
            char funcname[MAX_NAME_LEN];
            strncpy(funcname, entry->d_name, len - 4);
            funcname[len - 4] = '\0';
            strncpy(func_table[func_count].name, funcname, MAX_NAME_LEN - 1);
            func_table[func_count].name[MAX_NAME_LEN - 1] = '\0';
            func_table[func_count].ptr = NULL; // Lazy load
            func_table[func_count].len = 0;
            func_table[func_count].offset = 0;
            func_table[func_count].arg_count = -1;
            func_count++;
        }
    }
    closedir(dir);
}

static void* get_func_ptr(const char* name, int* arg_count_out){
    for (int i = 0; i < func_count; i++) {
        if (strcmp(func_table[i].name, name) == 0) {
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count);
                func_table[i].len = 0; // Update if needed
            }
            *arg_count_out = func_table[i].arg_count;
            return func_table[i].ptr;
        }
    }
    return NULL;
}

// ---------------- IR ----------------
typedef struct IR {
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

static void ir_init(IR* ir) { ir->stmts = NULL; ir->count = ir->capacity = 0; }

static IRStmt* ir_alloc_stmt(IR* ir) {
    if (ir->count >= ir->capacity) {
        int newcap = ir->capacity ? ir->capacity * 2 : 8;
        IRStmt* tmp = realloc(ir->stmts, sizeof(IRStmt) * newcap);
        if (!tmp) { perror("realloc IR"); exit(EXIT_FAILURE); }
        ir->stmts = tmp; ir->capacity = newcap;
    }
    IRStmt* s = &ir->stmts[ir->count++];
    memset(s, 0, sizeof(IRStmt));
    return s;
}

// ---------------- ArgBlock ----------------
typedef struct ArgBlock {
    int* args;
    int capacity;
    int used;
    struct ArgBlock* next;
} ArgBlock;

static ArgBlock* arg_blocks = NULL;

static int* arg_alloc(int n) {
    ArgBlock* b = arg_blocks;
    while (b) { 
        if (b->capacity - b->used >= n) { int* ptr = b->args + b->used; b->used += n; return ptr; } 
        b = b->next; 
    }
    int cap = (n > FIXED_ARG_POOL) ? n : FIXED_ARG_POOL;
    ArgBlock* nb = arena_alloc(sizeof(ArgBlock));
    nb->args = arena_alloc(sizeof(int) * cap);
    nb->capacity = cap; nb->used = n; nb->next = arg_blocks; arg_blocks = nb;
    return nb->args;
}

static void free_arg_blocks() {
    ArgBlock* b = arg_blocks;
    while (b) { ArgBlock* nx = b->next; /* No free since arena */ b = nx; }
    arg_blocks = NULL;
}

// ---------------- Dynamic var table ----------------
static void grow_var_table() {
    int new_size = var_table_size * 2;
    VarSlot** new_table = calloc(new_size, sizeof(VarSlot*));
    for (int i = 0; i < var_table_size; i++) {
        if (var_table[i]) {
            unsigned int h = hash_name((char*)var_table[i]->data, new_size);
            int placed = 0;
            for (int j = 0; j < new_size; j++) {
                int idx = (h + j) % new_size;
                if (!new_table[idx]) { new_table[idx] = var_table[i]; placed = 1; break; }
            }
            if (!placed) { /* Fallback, rare */ }
        }
    }
    free(var_table);
    var_table = new_table; var_table_size = new_size;
}

static int var_index(const char* name) {
    if (!var_table) { var_table = calloc(var_table_size, sizeof(VarSlot*)); }
    unsigned int h = hash_name(name, var_table_size);
    for (int i = 0; i < var_table_size; i++) {
        unsigned int idx = (h + i) % var_table_size;
        if (!var_table[idx]) {
            VarSlot* slot = pool_alloc();
            slot->data = strdup(name);
            var_table[idx] = slot;
            if (var_count >= env_alloc_size) {
                int new_size = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
                VarSlot** new_env = realloc(env_array, sizeof(VarSlot*) * new_size);
                env_array = new_env; env_alloc_size = new_size;
            }
            env_array[var_count] = slot;
            return var_count++;
        }
        if (strcmp((char*)var_table[idx]->data, name) == 0) {
            for (int j = 0; j < var_count; j++) if (env_array[j] == var_table[idx]) return j;
        }
    }
    grow_var_table();
    return var_index(name); // Recursive call after grow
}

// ---------------- Environment ----------------
static void init_env(int total_vars) {
    env_alloc_size = total_vars > 0 ? total_vars : (FIXED_VARS * 2);
    env_array = aligned_alloc(CACHE_LINE, sizeof(VarSlot*) * env_alloc_size);
    memset(env_array, 0, sizeof(VarSlot*) * env_alloc_size);
}

// ---------------- Executor structures ----------------
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
    WorkQueue* thread_queues; // Per-thread queues
} ExecContext;

// ---------------- Queue ----------------
static void queue_init(WorkQueue* q, int capacity) {
    q->buf = aligned_alloc(CACHE_LINE, sizeof(int) * capacity);
    q->capacity = capacity;
    atomic_init(&q->head, 0); atomic_init(&q->tail, 0);
}

static void queue_push(ExecContext* ctx, int val, int thread_id) {
    WorkQueue* q = &ctx->thread_queues[thread_id];
    int tail = atomic_fetch_add(&q->tail, 1) % q->capacity;
    q->buf[tail] = val;
}

static int queue_try_pop(ExecContext* ctx, int* out, int thread_id) {
    WorkQueue* q = &ctx->thread_queues[thread_id];
    int head = atomic_load(&q->head);
    int tail = atomic_load(&q->tail);
    if (head >= tail) return 0;
    if (atomic_compare_exchange_strong(&q->head, &head, head + 1)) { *out = q->buf[head % q->capacity]; return 1; }
    return 0;
}

static int steal_work(ExecContext* ctx, int* out, int thread_id) {
    for (int i = 0; i < ctx->max_threads; i++) {
        if (i == thread_id) continue;
        WorkQueue* q = &ctx->thread_queues[i];
        int head = atomic_load(&q->head);
        int tail = atomic_load(&q->tail);
        if (head >= tail) continue;
        if (atomic_compare_exchange_strong(&q->head, &head, head + 1)) { *out = q->buf[head % q->capacity]; return 1; }
    }
    return 0;
}

// ---------------- Executor ----------------
static void execute_single(IRStmt* s, ExecContext* ctx, long* args_buffer) {
    if (s->dead || s->executed) return;
    for (int i = 0; i < s->argc; i++) {
        int ai = s->arg_indices[i];
        VarSlot* arg = ctx->env_array[ai];
        args_buffer[i] = arg->constant ? arg->value : (long)arg->data;
    }
    VarSlot* lhs = ctx->env_array[s->lhs_index];
    if (s->inlined) {
        long val = 0; for (int i = 0; i < s->argc; i++) val += args_buffer[i]; // Generic sum, or extend for other ops
        lhs->value = val; lhs->constant = 0;
    } else if (s->func_ptr) {
        int expected_argc;
        if (get_func_ptr("dummy", &expected_argc)) {} // Placeholder; use actual name if needed
        if (expected_argc != -1 && s->argc != expected_argc) { /* Error */ return; }
        void (*fn)(long*, long*) = s->func_ptr;
        fn(&lhs->value, args_buffer);
        lhs->constant = 0;
    }
    s->executed = 1;
}

static void* worker_thread(void* arg) {
    long tid = (long)arg;
    ExecContext* ctx = (ExecContext*)pthread_getspecific(ctx_key); // Assume set
    long args_buffer[MAX_ARGS]; int idx;
    while (atomic_load(&ctx->remaining) > 0) {
        if (queue_try_pop(ctx, &idx, tid)) {
            execute_single(&ctx->stmts[idx], ctx, args_buffer);
            atomic_fetch_sub(&ctx->remaining, 1);
            Dependents* deps = &ctx->dependents[idx];
            for (int di = 0; di < deps->count; di++) {
                int d = deps->list[di];
                int prev = atomic_fetch_sub(&ctx->dep_remaining[d], 1);
                if (prev == 1) queue_push(ctx, d, tid % ctx->max_threads); // Balance push
            }
        } else if (steal_work(ctx, &idx, tid)) {
            execute_single(&ctx->stmts[idx], ctx, args_buffer);
            atomic_fetch_sub(&ctx->remaining, 1);
            Dependents* deps = &ctx->dependents[idx];
            for (int di = 0; di < deps->count; di++) {
                int d = deps->list[di];
                int prev = atomic_fetch_sub(&ctx->dep_remaining[d], 1);
                if (prev == 1) queue_push(ctx, d, tid);
            }
        } else {
            sched_yield();
        }
    }
    arena_reset(); // Reset thread-local arena
    return NULL;
}

static void build_dependents(ExecContext* ctx) {
    int n = ctx->stmt_count;
    ctx->dependents = calloc(n, sizeof(Dependents));
    for (int i = 0; i < n; i++) {
        ctx->dependents[i].capacity = 8; // Initial estimate
        ctx->dependents[i].list = malloc(sizeof(int) * 8);
    }
    for (int i = 0; i < n; i++) {
        IRStmt* s = &ctx->stmts[i];
        for (int p = 0; p < s->dep_count; p++) {
            int pred = s->dep_indices[p]; if (pred >= 0 && pred < n) {
                Dependents* deps = &ctx->dependents[pred];
                if (deps->count >= deps->capacity) {
                    deps->capacity *= 2;
                    deps->list = realloc(deps->list, sizeof(int) * deps->capacity);
                }
                deps->list[deps->count++] = i;
            }
        }
    }
}

static void free_dependents(ExecContext* ctx) {
    if (!ctx->dependents) return;
    for (int i = 0; i < ctx->stmt_count; i++)
        if (ctx->dependents[i].list) free(ctx->dependents[i].list);
    free(ctx->dependents); ctx->dependents = NULL;
}

static pthread_key_t ctx_key;
static void init_ctx_key() { pthread_key_create(&ctx_key, NULL); }

void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads) {
    if (max_threads <= 0) max_threads = MAX_THREADS_DEFAULT;
    init_ctx_key();
    ExecContext ctx = {0};
    ctx.stmts = stmts; ctx.stmt_count = stmt_count; ctx.env_array = env_array; ctx.max_threads = max_threads;
    ctx.dep_remaining = calloc(stmt_count, sizeof(atomic_int));
    for (int i = 0; i < stmt_count; i++) atomic_init(&ctx->dep_remaining[i], stmts[i].dep_count);
    build_dependents(&ctx);

    ctx.thread_queues = malloc(sizeof(WorkQueue) * max_threads);
    for (int i = 0; i < max_threads; i++) queue_init(&ctx->thread_queues[i], stmt_count / max_threads + 128);

    atomic_init(&ctx.remaining, stmt_count);
    int initial_push = 0;
    for (int i = 0; i < stmt_count; i++) if (stmts[i].dep_count == 0) {
        queue_push(&ctx, i, initial_push % max_threads);
        initial_push++;
    }

    pthread_t* threads = malloc(sizeof(pthread_t) * max_threads);
    for (long i = 0; i < max_threads; i++) {
        pthread_setspecific(ctx_key, &ctx);
        pthread_create(&threads[i], NULL, worker_thread, (void*)i);
    }
    for (int i = 0; i < max_threads; i++) pthread_join(threads[i], NULL);

    for (int i = 0; i < max_threads; i++) free(ctx.thread_queues[i].buf);
    free(ctx.thread_queues);
    free(threads);
    free(ctx.dep_remaining);
    free_dependents(&ctx);
}

// ---------------- Init environment ----------------
static void init_full_env(int total_vars) {
    init_env(total_vars);
}

// ---------------- Cleanup ----------------
static void cleanup() {
    free_arg_blocks();
    if (env_array) { free(env_array); env_array = NULL; }
    if (var_table) { free(var_table); var_table = NULL; }
    VarPoolChunk* c = dynamic_pool;
    while (c) { VarPoolChunk* nx = c->next; free(c->slots); /* arena for struct */ c = nx; }
    dynamic_pool = NULL;
    if (func_blob) munmap(func_blob, func_blob_size);
    if (func_table) { free(func_table); func_table = NULL; } // Free dynamic func_table
}

// ---------------- Parser ----------------
static IRStmt* parse_line(const char* line, IR* ir) {
    // Skip empty lines and comments
    while (isspace(*line)) line++;
    if (*line == '\0' || strncmp(line, "--", 2) == 0) return NULL;

    char lhs_name[MAX_NAME_LEN] = {0};
    char func_name[MAX_NAME_LEN] = {0};
    char args_buf[1024];
    int arg_count = 0;
    int arg_indices[MAX_ARGS];

    const char* eq = strchr(line, '=');
    if (!eq) return NULL; // invalid line
    size_t lhs_len = eq - line;
    while (lhs_len > 0 && isspace(line[lhs_len - 1])) lhs_len--;
    strncpy(lhs_name, line, lhs_len);
    lhs_name[lhs_len] = '\0';

    const char* paren = strchr(eq, '(');
    const char* semi = strchr(eq, ';');
    if (!paren || !semi) return NULL;

    size_t func_len = paren - eq - 1;
    while (func_len > 0 && isspace(*(eq + 1 + func_len - 1))) func_len--;
    strncpy(func_name, eq + 1, func_len);
    func_name[func_len] = '\0';

    size_t args_len = semi - paren - 1;
    strncpy(args_buf, paren + 1, args_len);
    args_buf[args_len] = '\0';

    // Tokenize arguments
    char* tok = strtok(args_buf, ",");
    while (tok && arg_count < MAX_ARGS) {
        while (isspace(*tok)) tok++;
        char* end = tok + strlen(tok) - 1;
        while (end > tok && isspace(*end)) { *end = '\0'; end--; }
        arg_indices[arg_count++] = var_index(tok);
        tok = strtok(NULL, ",");
    }

    // Build IRStmt
    IRStmt* stmt = ir_alloc_stmt(ir);
    stmt->lhs_index = var_index(lhs_name);
    stmt->argc = arg_count;
    stmt->arg_indices = arg_alloc(arg_count);
    memcpy(stmt->arg_indices, arg_indices, sizeof(int) * arg_count);
    stmt->func_ptr = get_func_ptr(func_name, &arg_count); // lazy load
    stmt->inlined = 0;
    stmt->dep_count = 0;
    stmt->dep_indices = NULL;
    stmt->dead = 0;
    stmt->executed = 0;

    return stmt;
}

static IR* parse_script_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) { perror("fopen script"); return NULL; }
    IR* ir = malloc(sizeof(IR));
    ir_init(ir);
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        parse_line(line, ir);
    }
    fclose(f);
    return ir;
}

// ---------------- Main ----------------
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.optivar>\n", argv[0]);
        return 1;
    }

    const char* script_path = argv[1];

    // Preload all functions (optional, directory ./funcs)
    preload_binfuncs("./funcs");

    // Parse script
    IR* ir = parse_script_file(script_path);
    if (!ir) { fprintf(stderr, "Failed to parse script.\n"); return 1; }

    // Initialize environment
    init_full_env(var_count);

    // Execute
    executor(ir->stmts, ir->count, env_array, MAX_THREADS_DEFAULT);

    // Print results
    for (int i = 0; i < var_count; i++) {
        VarSlot* v = env_array[i];
        printf("%s = %ld\n", (char*)v->data, v->value);
    }

    // Cleanup
    cleanup();
    free(ir->stmts);
    free(ir);

    return 0;
}

