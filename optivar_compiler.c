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
#include <fcntl.h>
#include <sys/sysinfo.h> // For sysconf(_SC_NPROCESSORS_ONLN)

#define MAX_IR 8192
#define DEFAULT_FIXED_VARS 4096 // Configurable via --fixed-vars
#define VAR_CHUNK_SIZE 8192
#define FIXED_ARG_POOL 256
#define MAX_NAME_LEN 128
#define CACHE_LINE 64
#define MAX_ARGS 16
#define MAX_THREADS_DEFAULT 8 // Fallback if sysconf fails
#define MIN_BIN_SIZE 16 // Minimum .bin file size for validation

// ---------------- Command-line Options ----------------
static int FIXED_VARS = DEFAULT_FIXED_VARS;
static int var_table_size = 2048; // Configurable via --table-size
static int single_threaded = 0; // Flag for single-threaded mode

// ---------------- VarSlot ----------------
typedef struct VarSlot {
    void* data; // Variable name
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
static VarSlot* fixed_pool = NULL; // Dynamically allocated based on FIXED_VARS
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

// ---------------- Hash Table (Chained) ----------------
typedef struct HashNode {
    VarSlot* slot;
    char* name;
    struct HashNode* next;
} HashNode;

static HashNode** var_table = NULL;
static pthread_mutex_t var_table_mutex = PTHREAD_MUTEX_INITIALIZER;

// ---------------- Hash Function ----------------
static inline unsigned int hash_name(const char* s, int table_size) {
    unsigned int h = 0;
    while (*s) h = (h * 31) + (unsigned char)(*s++);
    return h % table_size;
}

// ---------------- Arena Allocator ----------------
static __thread char* arena_ptr = NULL;
static __thread size_t arena_size = 0;

static void* arena_alloc(size_t size) {
    if (!arena_ptr || arena_size < size) {
        size_t new_size = size > 65536 ? size : 65536;
        char* new_arena = aligned_alloc(CACHE_LINE, new_size);
        if (!new_arena) { perror("aligned_alloc arena"); exit(EXIT_FAILURE); }
        if (arena_ptr) free(arena_ptr); // Free old arena
        arena_ptr = new_arena;
        arena_size = new_size;
    }
    void* ptr = arena_ptr;
    arena_ptr += size;
    arena_size -= size;
    return ptr;
}

static void arena_reset() {
    if (arena_ptr) free(arena_ptr); // Free arena memory
    arena_ptr = NULL;
    arena_size = 0;
}

// ---------------- Pool Allocator ----------------
static VarSlot* pool_alloc() {
    for (int i = 0; i < fixed_top; i++) {
        if (!fixed_pool[i].in_use) {
            fixed_pool[i].in_use = 1;
            fixed_pool[i].last_use = -1;
            fixed_pool[i].constant = 0;
            return &fixed_pool[i];
        }
    }
    if (fixed_top < FIXED_VARS) {
        VarSlot* slot = &fixed_pool[fixed_top++];
        slot->in_use = 1;
        slot->last_use = -1;
        slot->constant = 0;
        return slot;
    }
    VarPoolChunk* chunk = dynamic_pool;
    while (chunk) {
        for (int i = 0; i < chunk->capacity; i++) {
            if (!chunk->slots[i].in_use) {
                chunk->slots[i].in_use = 1;
                chunk->slots[i].last_use = -1;
                chunk->slots[i].constant = 0;
                return &chunk->slots[i];
            }
        }
        chunk = chunk->next;
    }
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* new_chunk = arena_alloc(sizeof(VarPoolChunk));
    new_chunk->slots = aligned_alloc(CACHE_LINE, cap * sizeof(VarSlot));
    if (!new_chunk->slots) { perror("aligned_alloc VarPoolChunk->slots"); exit(EXIT_FAILURE); }
    new_chunk->capacity = cap;
    new_chunk->next = dynamic_pool;
    dynamic_pool = new_chunk;
    new_chunk->slots[0].in_use = 1;
    new_chunk->slots[0].last_use = -1;
    new_chunk->slots[0].constant = 0;
    return &new_chunk->slots[0];
}

// ---------------- Function Table ----------------
typedef struct {
    char name[MAX_NAME_LEN];
    void* ptr;
    size_t len;
    size_t offset;
    int arg_count;
} FuncEntry;

static FuncEntry* func_table = NULL;
static int func_table_size = 256;
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

// ---------------- Lazy Load .bin Functions ----------------
static void* load_binfunc(const char* name, int* arg_count_out) {
    char path[512];
    snprintf(path, sizeof(path), "./funcs/%s.bin", name);
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: Function file %s not found\n", path);
        return NULL;
    }
    if (st.st_size < MIN_BIN_SIZE) {
        fprintf(stderr, "Error: Function file %s too small (%ld bytes)\n", path, st.st_size);
        return NULL;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open %s\n", path);
        return NULL;
    }
    void* ptr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Error: Failed to mmap %s\n", path);
        return NULL;
    }
    *arg_count_out = -1; // Placeholder; no metadata parsing
    return ptr;
}

static void preload_binfuncs(const char* dirpath) {
    if (!func_table) {
        func_table = calloc(func_table_size, sizeof(FuncEntry));
        if (!func_table) { perror("calloc func_table"); exit(EXIT_FAILURE); }
    }
    DIR* dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Error: Failed to open directory %s\n", dirpath);
        return;
    }
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

static void* get_func_ptr(const char* name, int* arg_count_out) {
    for (int i = 0; i < func_count; i++) {
        if (strcmp(func_table[i].name, name) == 0) {
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count);
                if (!func_table[i].ptr) {
                    fprintf(stderr, "Warning: Failed to load function %s\n", name);
                }
            }
            *arg_count_out = func_table[i].arg_count;
            return func_table[i].ptr;
        }
    }
    fprintf(stderr, "Error: Function %s not found in func_table\n", name);
    *arg_count_out = -1;
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
        ir->stmts = tmp;
        ir->capacity = newcap;
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
        if (b->capacity - b->used >= n) {
            int* ptr = b->args + b->used;
            b->used += n;
            return ptr;
        }
        b = b->next;
    }
    int cap = (n > FIXED_ARG_POOL) ? n : FIXED_ARG_POOL;
    ArgBlock* nb = arena_alloc(sizeof(ArgBlock));
    nb->args = arena_alloc(sizeof(int) * cap);
    nb->capacity = cap;
    nb->used = n;
    nb->next = arg_blocks;
    arg_blocks = nb;
    return nb->args;
}

static void free_arg_blocks() {
    arg_blocks = NULL; // Arena-based, no explicit free
}

// ---------------- Dynamic Var Table ----------------
static void grow_var_table() {
    int new_size = var_table_size * 2;
    HashNode** new_table = calloc(new_size, sizeof(HashNode*));
    if (!new_table) { perror("calloc var_table"); exit(EXIT_FAILURE); }
    for (int i = 0; i < var_table_size; i++) {
        HashNode* node = var_table[i];
        while (node) {
            HashNode* next = node->next;
            unsigned int h = hash_name(node->name, new_size);
            node->next = new_table[h];
            new_table[h] = node;
            node = next;
        }
    }
    free(var_table);
    var_table = new_table;
    var_table_size = new_size;
}

static int var_index(const char* name) {
    pthread_mutex_lock(&var_table_mutex);
    if (!var_table) var_table = calloc(var_table_size, sizeof(HashNode*));
    unsigned int h = hash_name(name, var_table_size);
    HashNode* node = var_table[h];
    while (node) {
        if (strcmp(node->name, name) == 0) {
            for (int j = 0; j < var_count; j++) {
                if (env_array[j] == node->slot) {
                    pthread_mutex_unlock(&var_table_mutex);
                    return j;
                }
            }
        }
        node = node->next;
    }
    VarSlot* slot = pool_alloc();
    slot->data = strdup(name);
    if (!slot->data) { perror("strdup var name"); exit(EXIT_FAILURE); }
    HashNode* new_node = arena_alloc(sizeof(HashNode));
    new_node->slot = slot;
    new_node->name = slot->data;
    new_node->next = var_table[h];
    var_table[h] = new_node;
    if (var_count >= env_alloc_size) {
        int new_size = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
        VarSlot** new_env = realloc(env_array, sizeof(VarSlot*) * new_size);
        if (!new_env) { perror("realloc env_array"); exit(EXIT_FAILURE); }
        env_array = new_env;
        env_alloc_size = new_size;
    }
    env_array[var_count] = slot;
    int idx = var_count++;
    pthread_mutex_unlock(&var_table_mutex);
    return idx;
}

// ---------------- Environment ----------------
static void init_env(int total_vars) {
    env_alloc_size = total_vars > 0 ? total_vars : (FIXED_VARS * 2);
    env_array = aligned_alloc(CACHE_LINE, sizeof(VarSlot*) * env_alloc_size);
    if (!env_array) { perror("aligned_alloc env_array"); exit(EXIT_FAILURE); }
    memset(env_array, 0, sizeof(VarSlot*) * env_alloc_size);
    fixed_pool = aligned_alloc(CACHE_LINE, sizeof(VarSlot) * FIXED_VARS);
    if (!fixed_pool) { perror("aligned_alloc fixed_pool"); exit(EXIT_FAILURE); }
    memset(fixed_pool, 0, sizeof(VarSlot) * FIXED_VARS);
}

// ---------------- Executor Structures ----------------
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
    WorkQueue* thread_queues;
} ExecContext;

// ---------------- Queue ----------------
static void queue_init(WorkQueue* q, int capacity) {
    q->buf = aligned_alloc(CACHE_LINE, sizeof(int) * capacity);
    if (!q->buf) { perror("aligned_alloc queue"); exit(EXIT_FAILURE); }
    q->capacity = capacity;
    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
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
    if (atomic_compare_exchange_strong(&q->head, &head, head + 1)) {
        *out = q->buf[head % q->capacity];
        return 1;
    }
    return 0;
}

static int steal_work(ExecContext* ctx, int* out, int thread_id) {
    for (int i = 0; i < ctx->max_threads; i++) {
        if (i == thread_id) continue;
        WorkQueue* q = &ctx->thread_queues[i];
        int head = atomic_load(&q->head);
        int tail = atomic_load(&q->tail);
        if (head >= tail) continue;
        if (atomic_compare_exchange_strong(&q->head, &head, head + 1)) {
            *out = q->buf[head % q->capacity];
            return 1;
        }
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
        long val = 0;
        for (int i = 0; i < s->argc; i++) val += args_buffer[i]; // Generic sum
        lhs->value = val;
        lhs->constant = 0;
    } else if (s->func_ptr) {
        int expected_argc = -1; // Placeholder
        if (expected_argc != -1 && s->argc != expected_argc) {
            fprintf(stderr, "Error: Function at stmt %d expects %d args, got %d\n",
                    (int)(s - ctx->stmts), expected_argc, s->argc);
            return;
        }
        void (*fn)(long*, long*) = s->func_ptr;
        fn(&lhs->value, args_buffer);
        lhs->constant = 0;
    } else {
        fprintf(stderr, "Error: No function pointer for stmt %d\n", (int)(s - ctx->stmts));
        return;
    }
    s->executed = 1;
}

static void* worker_thread(void* arg) {
    long tid = (long)arg;
    ExecContext* ctx = (ExecContext*)pthread_getspecific(ctx_key);
    long args_buffer[MAX_ARGS];
    int idx;
    while (atomic_load(&ctx->remaining) > 0) {
        if (queue_try_pop(ctx, &idx, tid)) {
            execute_single(&ctx->stmts[idx], ctx, args_buffer);
            atomic_fetch_sub(&ctx->remaining, 1);
            Dependents* deps = &ctx->dependents[idx];
            for (int di = 0; di < deps->count; di++) {
                int d = deps->list[di];
                int prev = atomic_fetch_sub(&ctx->dep_remaining[d], 1);
                if (prev == 1) queue_push(ctx, d, tid % ctx->max_threads);
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
    arena_reset();
    return NULL;
}

static void build_dependents(ExecContext* ctx) {
    int n = ctx->stmt_count;
    ctx->dependents = calloc(n, sizeof(Dependents));
    if (!ctx->dependents) { perror("calloc dependents"); exit(EXIT_FAILURE); }
    for (int i = 0; i < n; i++) {
        ctx->dependents[i].capacity = 8;
        ctx->dependents[i].list = malloc(sizeof(int) * 8);
        if (!ctx->dependents[i].list) { perror("malloc dependents list"); exit(EXIT_FAILURE); }
    }
    for (int i = 0; i < n; i++) {
        IRStmt* s = &ctx->stmts[i];
        for (int p = 0; p < s->dep_count; p++) {
            int pred = s->dep_indices[p];
            if (pred >= 0 && pred < n) {
                Dependents* deps = &ctx->dependents[pred];
                if (deps->count >= deps->capacity) {
                    deps->capacity *= 2;
                    deps->list = realloc(deps->list, sizeof(int) * deps->capacity);
                    if (!deps->list) { perror("realloc dependents list"); exit(EXIT_FAILURE); }
                }
                deps->list[deps->count++] = i;
            }
        }
    }
}

static void free_dependents(ExecContext* ctx) {
    if (!ctx->dependents) return;
    for (int i = 0; i < ctx->stmt_count; i++) {
        if (ctx->dependents[i].list) free(ctx->dependents[i].list);
    }
    free(ctx->dependents);
    ctx->dependents = NULL;
}

static pthread_key_t ctx_key;
static void init_ctx_key() { pthread_key_create(&ctx_key, NULL); }

void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads) {
    if (single_threaded) max_threads = 1; // Override for single-threaded mode
    init_ctx_key();
    ExecContext ctx = {0};
    ctx.stmts = stmts;
    ctx.stmt_count = stmt_count;
    ctx.env_array = env_array;
    ctx.max_threads = max_threads;
    ctx.dep_remaining = calloc(stmt_count, sizeof(atomic_int));
    if (!ctx.dep_remaining) { perror("calloc dep_remaining"); exit(EXIT_FAILURE); }
    for (int i = 0; i < stmt_count; i++) atomic_init(&ctx->dep_remaining[i], stmts[i].dep_count);
    build_dependents(&ctx);

    ctx.thread_queues = malloc(sizeof(WorkQueue) * max_threads);
    if (!ctx.thread_queues) { perror("malloc thread_queues"); exit(EXIT_FAILURE); }
    for (int i = 0; i < max_threads; i++) queue_init(&ctx->thread_queues[i], stmt_count / max_threads + 128);

    atomic_init(&ctx->remaining, stmt_count);
    int initial_push = 0;
    for (int i = 0; i < stmt_count; i++) {
        if (stmts[i].dep_count == 0) {
            queue_push(&ctx, i, initial_push % max_threads);
            initial_push++;
        }
    }

    pthread_t* threads = malloc(sizeof(pthread_t) * max_threads);
    if (!threads) { perror("malloc threads"); exit(EXIT_FAILURE); }
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

// ---------------- Dependency Analysis ----------------
static void compute_dependencies(IR* ir) {
    for (int i = 0; i < ir->count; i++) {
        IRStmt* stmt = &ir->stmts[i];
        int dep_indices[MAX_ARGS];
        int dep_count = 0;
        for (int j = 0; j < stmt->argc; j++) {
            int arg_idx = stmt->arg_indices[j];
            for (int k = 0; k < i; k++) {
                if (ir->stmts[k].lhs_index == arg_idx && !ir->stmts[k].dead) {
                    if (dep_count < MAX_ARGS) dep_indices[dep_count++] = k;
                }
            }
        }
        stmt->dep_count = dep_count;
        if (dep_count > 0) {
            stmt->dep_indices = arg_alloc(dep_count);
            memcpy(stmt->dep_indices, dep_indices, sizeof(int) * dep_count);
        }
    }
}

// ---------------- Init Environment ----------------
static void init_full_env(int total_vars) {
    init_env(total_vars);
}

// ---------------- Cleanup ----------------
static void cleanup() {
    free_arg_blocks();
    if (env_array) {
        for (int i = 0; i < var_count; i++) {
            if (env_array[i] && env_array[i]->data) free(env_array[i]->data);
        }
        free(env_array);
        env_array = NULL;
    }
    if (var_table) {
        for (int i = 0; i < var_table_size; i++) {
            HashNode* node = var_table[i];
            while (node) {
                HashNode* next = node->next;
                node = next; // No free; arena-based
            }
        }
        free(var_table);
        var_table = NULL;
    }
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        VarPoolChunk* nx = c->next;
        free(c->slots); // Free slots
        c = nx; // Arena-based struct
    }
    dynamic_pool = NULL;
    if (func_blob) munmap(func_blob, func_blob_size);
    if (func_table) {
        for (int i = 0; i < func_count; i++) {
            if (func_table[i].ptr) munmap(func_table[i].ptr, func_table[i].len);
        }
        free(func_table);
        func_table = NULL;
    }
    arena_reset();
}

// ---------------- Parser ----------------
static IRStmt* parse_line(const char* line, IR* ir, int stmt_idx) {
    while (isspace(*line)) line++;
    if (*line == '\0' || strncmp(line, "--", 2) == 0) return NULL;

    char lhs_name[MAX_NAME_LEN] = {0};
    char func_name[MAX_NAME_LEN] = {0};
    char args_buf[1024];
    int arg_count = 0;
    int arg_indices[MAX_ARGS];

    const char* eq = strchr(line, '=');
    if (!eq) {
        fprintf(stderr, "Error: Invalid line (no '='): %s\n", line);
        return NULL;
    }
    size_t lhs_len = eq - line;
    while (lhs_len > 0 && isspace(line[lhs_len - 1])) lhs_len--;
    if (lhs_len >= MAX_NAME_LEN) {
        fprintf(stderr, "Error: LHS name too long: %s\n", line);
        return NULL;
    }
    strncpy(lhs_name, line, lhs_len);
    lhs_name[lhs_len] = '\0';

    const char* paren = strchr(eq, '(');
    const char* semi = strchr(eq, ';');
    if (!paren || !semi) {
        fprintf(stderr, "Error: Invalid function call syntax: %s\n", line);
        return NULL;
    }

    size_t func_len = paren - eq - 1;
    while (func_len > 0 && isspace(*(eq + 1 + func_len - 1))) func_len--;
    if (func_len >= MAX_NAME_LEN) {
        fprintf(stderr, "Error: Function name too long: %s\n", line);
        return NULL;
    }
    strncpy(func_name, eq + 1, func_len);
    func_name[func_len] = '\0';

    size_t args_len = semi - paren - 1;
    if (args_len >= 1024) {
        fprintf(stderr, "Error: Arguments too long: %s\n", line);
        return NULL;
    }
    strncpy(args_buf, paren + 1, args_len);
    args_buf[args_len] = '\0';

    char* tok = strtok(args_buf, ",");
    while (tok && arg_count < MAX_ARGS) {
        while (isspace(*tok)) tok++;
        char* end = tok + strlen(tok) - 1;
        while (end > tok && isspace(*end)) { *end = '\0'; end--; }
        if (*tok) arg_indices[arg_count++] = var_index(tok);
        tok = strtok(NULL, ",");
    }

    IRStmt* stmt = ir_alloc_stmt(ir);
    stmt->lhs_index = var_index(lhs_name);
    stmt->argc = arg_count;
    stmt->arg_indices = arg_alloc(arg_count);
    memcpy(stmt->arg_indices, arg_indices, sizeof(int) * arg_count);
    stmt->func_ptr = get_func_ptr(func_name, &stmt->arg_count);
    stmt->inlined = 0;
    stmt->dep_count = 0;
    stmt->dep_indices = NULL;
    stmt->dead = 0;
    stmt->executed = 0;
    return stmt;
}

static IR* parse_script_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: Failed to open script %s\n", path);
        return NULL;
    }
    IR* ir = malloc(sizeof(IR));
    if (!ir) { perror("malloc IR"); fclose(f); return NULL; }
    ir_init(ir);
    char line[1024];
    int stmt_idx = 0;
    while (fgets(line, sizeof(line), f)) {
        parse_line(line, ir, stmt_idx++);
    }
    fclose(f);
    compute_dependencies(ir); // Compute dependencies after parsing
    return ir;
}

// ---------------- Parse Command-Line Arguments ----------------
static void parse_args(int argc, char** argv, char** script_path, int* max_threads) {
    *script_path = NULL;
    *max_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (*max_threads <= 0) *max_threads = MAX_THREADS_DEFAULT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--single-thread") == 0) {
            single_threaded = 1;
        } else if (strncmp(argv[i], "--fixed-vars=", 13) == 0) {
            FIXED_VARS = atoi(argv[i] + 13);
            if (FIXED_VARS <= 0) FIXED_VARS = DEFAULT_FIXED_VARS;
        } else if (strncmp(argv[i], "--table-size=", 13) == 0) {
            var_table_size = atoi(argv[i] + 13);
            if (var_table_size <= 0) var_table_size = 2048;
        } else if (argv[i][0] != '-') {
            *script_path = argv[i];
        }
    }

    if (!*script_path) {
        fprintf(stderr, "Usage: %s <script.optivar> [--single-thread] [--fixed-vars=N] [--table-size=N]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

// ---------------- Main ----------------
int main(int argc, char** argv) {
    char* script_path;
    int max_threads;
    parse_args(argc, argv, &script_path, &max_threads);

    preload_binfuncs("./funcs");
    IR* ir = parse_script_file(script_path);
    if (!ir) {
        fprintf(stderr, "Failed to parse script %s\n", script_path);
        cleanup();
        return 1;
    }

    init_full_env(var_count);
    executor(ir->stmts, ir->count, env_array, max_threads);

    for (int i = 0; i < var_count; i++) {
        VarSlot* v = env_array[i];
        printf("%s = %ld\n", (char*)v->data, v->value);
    }

    cleanup();
    free(ir->stmts);
    free(ir);
    return 0;
}
