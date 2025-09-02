// optivar.c -- superoptimized, memory-safe, minimal, scalable IR executor
// Build: gcc -O3 -march=native -lz -o optivar optivar.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <zlib.h>
#include <time.h>

//
// Tunables
//
#define DEFAULT_FIXED_VARS 4096
#define VAR_CHUNK_SIZE 8192
#define FIXED_ARG_POOL 256
#define MAX_NAME_LEN 128
#define CACHE_LINE 64
#define MAX_ARGS 16
#define MIN_BIN_SIZE 16
#define BIN_MAGIC 0xDEADBEEF

//
// Config (modifiable by argv)
//
static int FIXED_VARS = DEFAULT_FIXED_VARS;
static int var_table_size = 4096;

//
// Basic types
//
typedef struct VarSlot {
    void* data;     // either pointer payload or strdup'd name
    int in_use;
    int last_use;
    int constant;   // 1 if value valid in 'value'
    long value;     // numeric value if constant
    char pad[CACHE_LINE - sizeof(void*) - 4*sizeof(int) - sizeof(long)];
} VarSlot;

typedef struct IRStmt {
    int lhs_index;
    void* func_ptr;        // mapped function pointer or NULL
    int argc;
    int* arg_indices;      // indices into env_array
    int dead;
    int inlined;           // 1 if inlined simple op
    int executed;
    char pad[CACHE_LINE - 7*sizeof(int) - sizeof(void*) - sizeof(int*)];
} IRStmt;

typedef struct IR {
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

//
// Pools & environment
//
typedef struct VarPoolChunk {
    VarSlot* slots;
    int capacity;
    struct VarPoolChunk* next;
} VarPoolChunk;

// global containers
static VarSlot* fixed_pool = NULL;
static int fixed_top = 0;
static VarPoolChunk* dynamic_pool = NULL;

// environment mapping
static VarSlot** env_array = NULL;
static int var_count = 0;
static int env_alloc_size = 0;

// hash node for name -> slot
typedef struct HashNode {
    VarSlot* slot;
    char* name;         // points into slot->data (strdup)
    struct HashNode* next;
} HashNode;
static HashNode** var_table = NULL;

//
// Function table for .bin functions
//
typedef struct {
    char name[MAX_NAME_LEN];
    void* ptr;
    size_t len;
    int arg_count;
} FuncEntry;

static FuncEntry* func_table = NULL;
static int func_table_size = 256;
static int func_count = 0;

//
// Bin header
//
typedef struct {
    uint32_t magic;
    int32_t arg_count;
    uint32_t code_crc;
    uint32_t code_size;
} BinHeader;

//
// Thread-local arena allocator: per-thread fast bump allocator.
//
static __thread char* arena_ptr = NULL;
static __thread size_t arena_size = 0;

static void* thread_arena_alloc(size_t size) {
    // align to 16
    size_t a = (size + 15) & ~((size_t)15);
    if (!arena_ptr || arena_size < a) {
        size_t new_size = a > 65536 ? a : 65536;
        // posix_memalign to respect alignment
        void* mem = NULL;
        if (posix_memalign(&mem, CACHE_LINE, new_size) != 0 || !mem) {
            perror("posix_memalign (arena)");
            exit(EXIT_FAILURE);
        }
        // free old arena if exists
        if (arena_ptr) free(arena_ptr);
        arena_ptr = mem;
        arena_size = new_size;
    }
    void* out = arena_ptr;
    arena_ptr += a;
    arena_size -= a;
    return out;
}

static void thread_arena_reset() {
    if (arena_ptr) {
        free(arena_ptr);
        arena_ptr = NULL;
        arena_size = 0;
    }
}

//
// Pool allocator for VarSlot
//
static VarSlot* pool_alloc() {
    // try fixed pool quickly (no lock; these are global but only allocated at init/parse time
    for (int i = 0; i < fixed_top; ++i) {
        if (!fixed_pool[i].in_use) {
            fixed_pool[i].in_use = 1;
            fixed_pool[i].last_use = -1;
            fixed_pool[i].constant = 0;
            fixed_pool[i].data = NULL;
            fixed_pool[i].value = 0;
            return &fixed_pool[i];
        }
    }
    if (fixed_top < FIXED_VARS) {
        VarSlot* s = &fixed_pool[fixed_top++];
        s->in_use = 1;
        s->last_use = -1;
        s->constant = 0;
        s->data = NULL;
        s->value = 0;
        return s;
    }
    // search dynamic chunks
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        for (int i = 0; i < c->capacity; ++i) {
            if (!c->slots[i].in_use) {
                c->slots[i].in_use = 1;
                c->slots[i].last_use = -1;
                c->slots[i].constant = 0;
                c->slots[i].data = NULL;
                c->slots[i].value = 0;
                return &c->slots[i];
            }
        }
        c = c->next;
    }
    // create new chunk from thread arena (fast)
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* nc = thread_arena_alloc(sizeof(VarPoolChunk));
    nc->slots = aligned_alloc(CACHE_LINE, cap * sizeof(VarSlot));
    if (!nc->slots) { perror("aligned_alloc slots"); exit(EXIT_FAILURE); }
    nc->capacity = cap;
    nc->next = dynamic_pool;
    dynamic_pool = nc;
    memset(nc->slots, 0, cap * sizeof(VarSlot));
    nc->slots[0].in_use = 1;
    nc->slots[0].last_use = -1;
    nc->slots[0].constant = 0;
    return &nc->slots[0];
}

//
// Hash helper
//
static inline unsigned int hash_name(const char* s, int table_size) {
    unsigned int h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)(*s++);
        h *= 16777619u;
    }
    return h % (unsigned int)table_size;
}

//
// Dynamic func table grow
//
static void grow_func_table() {
    int new_size = func_table_size * 2;
    FuncEntry* nt = realloc(func_table, sizeof(FuncEntry) * new_size);
    if (!nt) { perror("realloc func_table"); exit(EXIT_FAILURE); }
    memset(nt + func_table_size, 0, sizeof(FuncEntry) * (new_size - func_table_size));
    func_table = nt;
    func_table_size = new_size;
}

//
// load .bin function with CRC32 & mmap; returns executable pointer
//
static void* load_binfunc(const char* name, int* arg_count_out, size_t* len_out) {
    char path[512];
    snprintf(path, sizeof(path), "./funcs/%s.bin", name);
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: %s not found\n", path);
        return NULL;
    }
    if (st.st_size < (ssize_t)(sizeof(BinHeader) + MIN_BIN_SIZE)) {
        fprintf(stderr, "Error: %s too small\n", path);
        return NULL;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open bin"); return NULL; }
    BinHeader hdr;
    if (read(fd, &hdr, sizeof(BinHeader)) != (ssize_t)sizeof(BinHeader)) {
        fprintf(stderr, "Error: read header %s\n", path);
        close(fd);
        return NULL;
    }
    if (hdr.magic != BIN_MAGIC) {
        fprintf(stderr, "Error: bad magic in %s\n", path);
        close(fd); return NULL;
    }
    if (hdr.arg_count < 0) {
        fprintf(stderr, "Error: bad arg_count in %s\n", path);
        close(fd); return NULL;
    }
    uint32_t expected_code_size = hdr.code_size;
    uint32_t actual_code_size = st.st_size - sizeof(BinHeader);
    if (expected_code_size != actual_code_size) {
        fprintf(stderr, "Error: code_size mismatch in %s\n", path);
        close(fd); return NULL;
    }
    if (lseek(fd, sizeof(BinHeader), SEEK_SET) < 0) { perror("lseek"); close(fd); return NULL; }
    char* buf = malloc(actual_code_size);
    if (!buf) { perror("malloc code"); close(fd); return NULL; }
    if (read(fd, buf, actual_code_size) != (ssize_t)actual_code_size) {
        fprintf(stderr, "Error: read code %s\n", path); free(buf); close(fd); return NULL;
    }
    uint32_t crc = crc32(0, (unsigned char*)buf, actual_code_size);
    if (crc != hdr.code_crc) {
        fprintf(stderr, "Error: CRC mismatch in %s (got 0x%x need 0x%x)\n", path, crc, hdr.code_crc);
        free(buf); close(fd); return NULL;
    }
    // Map code executable: map file region starting at offset sizeof(BinHeader)
    void* mapped = mmap(NULL, actual_code_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, sizeof(BinHeader));
    if (mapped == MAP_FAILED) { perror("mmap"); free(buf); close(fd); return NULL; }
    free(buf);
    close(fd);
    *arg_count_out = hdr.arg_count;
    *len_out = actual_code_size;
    return mapped;
}

//
// Preload functions in directory (names only); actual mapping deferred until get_func_ptr
//
static void preload_binfuncs(const char* dirpath) {
    if (!func_table) {
        func_table = calloc(func_table_size, sizeof(FuncEntry));
        if (!func_table) { perror("calloc func_table"); exit(EXIT_FAILURE); }
    }
    DIR* d = opendir(dirpath);
    if (!d) { fprintf(stderr, "Warning: cannot open %s\n", dirpath); return; }
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_type != DT_REG && e->d_type != DT_UNKNOWN) continue;
        size_t n = strlen(e->d_name);
        if (n > 4 && strcmp(e->d_name + n - 4, ".bin") == 0) {
            if (func_count >= func_table_size) grow_func_table();
            size_t namelen = n - 4;
            if (namelen >= MAX_NAME_LEN) continue;
            strncpy(func_table[func_count].name, e->d_name, namelen);
            func_table[func_count].name[namelen] = '\0';
            func_table[func_count].ptr = NULL;
            func_table[func_count].len = 0;
            func_table[func_count].arg_count = -1;
            func_count++;
        }
    }
    closedir(d);
}

static void* get_func_ptr(const char* name, int* arg_count_out, size_t* len_out) {
    if (!func_table) {
        *arg_count_out = -1; *len_out = 0;
        return NULL;
    }
    for (int i = 0; i < func_count; ++i) {
        if (strcmp(func_table[i].name, name) == 0) {
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count, &func_table[i].len);
                if (!func_table[i].ptr) {
                    *arg_count_out = -1; *len_out = 0;
                    return NULL;
                }
            }
            *arg_count_out = func_table[i].arg_count;
            *len_out = func_table[i].len;
            void* p = func_table[i].ptr;
            return p;
        }
    }
    *arg_count_out = -1; *len_out = 0;
    return NULL;
}

//
// IR helpers
//
static void ir_init(IR* ir) { ir->stmts = NULL; ir->count = ir->capacity = 0; }
static IRStmt* ir_alloc_stmt(IR* ir) {
    if (ir->count >= ir->capacity) {
        int newc = ir->capacity ? ir->capacity * 2 : 16;
        IRStmt* tmp = realloc(ir->stmts, sizeof(IRStmt) * newc);
        if (!tmp) { perror("realloc IR"); exit(EXIT_FAILURE); }
        ir->stmts = tmp;
        ir->capacity = newc;
    }
    IRStmt* s = &ir->stmts[ir->count++];
    memset(s, 0, sizeof(IRStmt));
    return s;
}

//
// Arg block allocator (arena-backed)
//
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
            int* out = b->args + b->used;
            b->used += n;
            return out;
        }
        b = b->next;
    }
    int cap = (n > FIXED_ARG_POOL) ? n : FIXED_ARG_POOL;
    ArgBlock* nb = thread_arena_alloc(sizeof(ArgBlock));
    nb->args = thread_arena_alloc(sizeof(int) * cap);
    nb->capacity = cap;
    nb->used = n;
    nb->next = arg_blocks;
    arg_blocks = nb;
    return nb->args;
}

static void free_arg_blocks() {
    arg_blocks = NULL; // arena reset will free memory
}

//
// var table grow (rebuild)
//
static void grow_var_table() {
    int new_size = var_table_size * 2;
    HashNode** nt = calloc(new_size, sizeof(HashNode*));
    if (!nt) { perror("calloc var_table"); exit(EXIT_FAILURE); }
    for (int i = 0; i < var_table_size; ++i) {
        HashNode* n = var_table ? var_table[i] : NULL;
        while (n) {
            HashNode* nx = n->next;
            unsigned int h = hash_name(n->name, new_size);
            n->next = nt[h];
            nt[h] = n;
            n = nx;
        }
    }
    free(var_table);
    var_table = nt;
    var_table_size = new_size;
}

static int var_index(const char* name) {
    if (!var_table) {
        var_table = calloc(var_table_size, sizeof(HashNode*));
        if (!var_table) { perror("calloc var_table"); exit(EXIT_FAILURE); }
    }
    unsigned int h = hash_name(name, var_table_size);
    HashNode* node = var_table[h];
    while (node) {
        if (strcmp(node->name, name) == 0) {
            // find index in env_array
            for (int j = 0; j < var_count; ++j) {
                if (env_array[j] == node->slot) {
                    return j;
                }
            }
        }
        node = node->next;
    }
    // add new var
    VarSlot* s = pool_alloc();
    s->data = strdup(name);
    if (!s->data) { perror("strdup"); exit(EXIT_FAILURE); }
    HashNode* hn = thread_arena_alloc(sizeof(HashNode));
    hn->slot = s;
    hn->name = s->data;
    hn->next = var_table[h];
    var_table[h] = hn;
    if (var_count >= env_alloc_size) {
        int ns = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
        VarSlot** ne = realloc(env_array, sizeof(VarSlot*) * ns);
        if (!ne) { perror("realloc env"); exit(EXIT_FAILURE); }
        env_array = ne;
        env_alloc_size = ns;
    }
    env_array[var_count] = s;
    int idx = var_count++;
    return idx;
}

//
// initialize env
//
static void init_env(int total_vars) {
    env_alloc_size = total_vars > 0 ? total_vars : (FIXED_VARS * 2);
    env_array = aligned_alloc(CACHE_LINE, sizeof(VarSlot*) * env_alloc_size);
    if (!env_array) { perror("aligned_alloc env"); exit(EXIT_FAILURE); }
    memset(env_array, 0, sizeof(VarSlot*) * env_alloc_size);
    fixed_pool = aligned_alloc(CACHE_LINE, sizeof(VarSlot) * FIXED_VARS);
    if (!fixed_pool) { perror("aligned_alloc fixed_pool"); exit(EXIT_FAILURE); }
    memset(fixed_pool, 0, sizeof(VarSlot) * FIXED_VARS);
}

//
// Execution context and dependent graph
//

static void execute_single(IRStmt* s, VarSlot** env, long* args_buffer) {
    if (!s || s->dead || s->executed) return;
    // gather args
    for (int i = 0; i < s->argc; ++i) {
        int ai = s->arg_indices[i];
        if (ai < 0 || ai >= var_count) { args_buffer[i] = 0; continue; }
        VarSlot* a = env[ai];
        if (!a) { args_buffer[i] = 0; continue; }
        args_buffer[i] = a->constant ? a->value : (long)a->data;
    }
    VarSlot* lhs = env[s->lhs_index];
    if (!lhs) return;
    if (s->inlined) {
        long acc = 0;
        int all_const = 1;
        for (int i = 0; i < s->argc; ++i) {
            int ai = s->arg_indices[i];
            VarSlot* a = env[ai];
            if (!a || !a->constant) all_const = 0;
            acc += args_buffer[i];
        }
        lhs->value = acc;
        lhs->constant = all_const;
    } else if (s->func_ptr) {
        // expected signature: void fn(long* out, long* args)
        void (*fn)(long*, long*) = s->func_ptr;
        fn(&lhs->value, args_buffer);
        lhs->constant = 0;
    } else {
        // unknown operation
        lhs->constant = 0;
    }
    s->executed = 1;
}

//
// executor entry
//
static void executor(IRStmt* stmts, int stmt_count, VarSlot** env, int max_threads) {
    (void)max_threads;
    long args_buffer[MAX_ARGS];
    for (int i = 0; i < stmt_count; ++i) {
        execute_single(&stmts[i], env, args_buffer);
    }
}

//
// cleanup resources
//
static void cleanup_all() {
    free_arg_blocks();
    if (env_array) {
        for (int i = 0; i < var_count; ++i) {
            if (env_array[i] && env_array[i]->data) free(env_array[i]->data);
        }
        free(env_array);
        env_array = NULL;
    }
    if (var_table) {
        free(var_table);
        var_table = NULL;
    }
    if (fixed_pool) {
        free(fixed_pool);
        fixed_pool = NULL;
    }
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        VarPoolChunk* nx = c->next;
        if (c->slots) free(c->slots);
        c = nx;
    }
    dynamic_pool = NULL;
    if (func_table) {
        for (int i = 0; i < func_count; ++i) {
            if (func_table[i].ptr && func_table[i].len > 0) {
                munmap(func_table[i].ptr, func_table[i].len);
            }
        }
        free(func_table);
        func_table = NULL;
    }
    thread_arena_reset();
}

static void atexit_cleanup() { cleanup_all(); }

//
// Parser: lines of form
//   var = func(arg1, arg2, ...);
// comments: lines starting with -- or empty
//
static IRStmt* parse_line(const char* line, IR* ir) {
    const char* p = line;
    while (isspace((unsigned char)*p)) ++p;
    if (*p == '\0') return NULL;
    if (p[0] == '-' && p[1] == '-') return NULL;
    // find '='
    const char* eq = strchr(p, '=');
    if (!eq) { fprintf(stderr, "Parse error: no '=' in line: %s\n", line); return NULL; }
    // LHS
    const char* q = eq - 1;
    while (q >= p && isspace((unsigned char)*q)) --q;
    const char* lhs_start = p;
    size_t lhs_len = (q >= p) ? (size_t)(q - p + 1) : 0;
    if (lhs_len == 0 || lhs_len >= MAX_NAME_LEN) { fprintf(stderr, "Parse error: bad LHS\n"); return NULL; }
    char lhs[MAX_NAME_LEN]; strncpy(lhs, lhs_start, lhs_len); lhs[lhs_len] = '\0';
    // find '(' and trailing ';'
    const char* paren = strchr(eq, '(');
    const char* semi = strchr(eq, ';');
    if (!paren || !semi || semi < paren) { fprintf(stderr, "Parse error: bad call syntax\n"); return NULL; }
    // function name between eq+1 and paren-1
    const char* fname_start = eq + 1;
    while (isspace((unsigned char)*fname_start)) ++fname_start;
    const char* ftmp = paren - 1;
    while (ftmp > fname_start && isspace((unsigned char)*ftmp)) --ftmp;
    size_t fnlen = (size_t)(ftmp - fname_start + 1);
    if (fnlen == 0 || fnlen >= MAX_NAME_LEN) { fprintf(stderr, "Parse error: bad func name\n"); return NULL; }
    char fname[MAX_NAME_LEN]; strncpy(fname, fname_start, fnlen); fname[fnlen] = '\0';
    // args between paren+1 and semi-1
    const char* args_start = paren + 1;
    const char* args_end = semi - 1;
    while (args_start <= args_end && isspace((unsigned char)*args_start)) ++args_start;
    while (args_end >= args_start && isspace((unsigned char)*args_end)) --args_end;
    size_t args_len = (args_end >= args_start) ? (size_t)(args_end - args_start + 1) : 0;
    char* argsbuf = NULL;
    if (args_len > 0) {
        argsbuf = malloc(args_len + 1);
        if (!argsbuf) { perror("malloc argsbuf"); exit(EXIT_FAILURE); }
        strncpy(argsbuf, args_start, args_len);
        argsbuf[args_len] = '\0';
    } else {
        argsbuf = strdup("");
    }
    // tokenize by comma
    int arg_count = 0;
    int arg_indices[MAX_ARGS];
    char* tok = strtok(argsbuf, ",");
    while (tok && arg_count < MAX_ARGS) {
        // trim
        while (isspace((unsigned char)*tok)) ++tok;
        char* end = tok + strlen(tok) - 1;
        while (end > tok && isspace((unsigned char)*end)) { *end = '\0'; --end; }
        if (*tok == '\0') { tok = strtok(NULL, ","); continue; }
        arg_indices[arg_count++] = var_index(tok);
        tok = strtok(NULL, ",");
    }
    free(argsbuf);
    IRStmt* s = ir_alloc_stmt(ir);
    s->lhs_index = var_index(lhs);
    s->argc = arg_count;
    s->arg_indices = arg_alloc(arg_count);
    memcpy(s->arg_indices, arg_indices, sizeof(int) * arg_count);
    size_t flen = 0;
    s->func_ptr = get_func_ptr(fname, &s->arg_count, &flen);
    // if func_ptr == NULL -> we'll leave it NULL (error will be reported at execution)
    s->inlined = 0;
    s->dead = 0;
    s->executed = 0;
    return s;
}

static IR* parse_script_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) { perror("fopen script"); return NULL; }
    IR* ir = malloc(sizeof(IR));
    ir_init(ir);
    char* line = NULL;
    size_t ls = 0;
    while (getline(&line, &ls, f) != -1) {
        parse_line(line, ir);
    }
    free(line);
    fclose(f);
    return ir;
}

//
// Command line parse
//
static void parse_args(int argc, char** argv, char** script_path, int* max_threads) {
    *script_path = NULL;
    *max_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (*max_threads <= 0) *max_threads = 8;
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--fixed-vars=", 13) == 0) {
            FIXED_VARS = atoi(argv[i] + 13);
            if (FIXED_VARS <= 0) FIXED_VARS = DEFAULT_FIXED_VARS;
        } else if (strncmp(argv[i], "--table-size=", 13) == 0) {
            var_table_size = atoi(argv[i] + 13);
            if (var_table_size <= 0) var_table_size = 4096;
        } else if (argv[i][0] != '-') {
            *script_path = argv[i];
        }
    }
    if (!*script_path) {
        fprintf(stderr, "Usage: %s <script.optivar> [--fixed-vars=N] [--table-size=N]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

//
// main
//
int main(int argc, char** argv) {
    atexit(atexit_cleanup);
    char* script_path = NULL;
    int max_threads = 0;
    parse_args(argc, argv, &script_path, &max_threads);
    // init
    preload_binfuncs("./funcs");
    IR* ir = parse_script_file(script_path);
    if (!ir) { cleanup_all(); return 1; }
    // initialize environment with discovered var_count
    init_env(var_count);
    // execute
    executor(ir->stmts, ir->count, env_array, max_threads);
    // print results
    for (int i = 0; i < var_count; ++i) {
        VarSlot* v = env_array[i];
        const char* name = (v && v->data) ? (char*)v->data : "<anon>";
        long val = v ? v->value : 0;
        printf("%s = %ld\n", name, val);
    }
    // free IR
    if (ir->stmts) free(ir->stmts);
    free(ir);
    cleanup_all();
    return 0;
}
