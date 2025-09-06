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
#include <fcntl.h>
#include <zlib.h>
#include <limits.h>
#include <assert.h>

//
// Tunables
//
#define DEFAULT_FIXED_VARS 4096
#define VAR_CHUNK_SIZE 8192
#define MAX_NAME_LEN 128
#define CACHE_LINE 64
#define MIN_BIN_SIZE 16
#define BIN_MAGIC 0xDEADBEEF

//
// Config (modifiable by argv)
//
static int FIXED_VARS = DEFAULT_FIXED_VARS;
static int var_table_size = 4096;
static int strict_mode = 0;  // 0 = skip missing functions, 1 = stop

//
// Basic types
//
typedef struct VarSlot {
    void* data;     // pointer to result (string, number, etc.) or strdup'd name
    int in_use;
    int last_use;
    long value;     // numeric value if needed
    char pad[CACHE_LINE - sizeof(void*) - 2*sizeof(int) - sizeof(long)];
} VarSlot;

// Forward declarations
struct BinContext;
struct IRStmt;
struct StatementBlock;

typedef struct IRStmt {
    int lhs_index;
    void* func_ptr;        // kept for backward compatibility
    int argc;
    void** args;           // Universal arguments (variables, literals, blocks, nested stmts)
    int dead;
    char func_name[MAX_NAME_LEN]; // store the function name
    char pad[CACHE_LINE - 3*sizeof(int) - sizeof(void*) - sizeof(void**) - MAX_NAME_LEN];
} IRStmt;

// Add static assertions after type definitions
static_assert(sizeof(VarSlot) % CACHE_LINE == 0, "VarSlot not cache-aligned");
static_assert(sizeof(IRStmt) % CACHE_LINE == 0, "IRStmt not cache-aligned");

// Enhanced bin function signature with universal type
typedef void* (*BinFunc)(void** args, int argc, struct BinContext* ctx);

// Context passed to bin functions
typedef struct BinContext {
    VarSlot** env;           // Full environment access
    struct FuncEntry* func_table;   // For bin-to-bin calls
    int func_count;
} BinContext;

typedef struct IR {
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

typedef struct StatementBlock {
    IRStmt* stmts;
    int count;
    int capacity;
} StatementBlock;

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
    int index;
    struct HashNode* next;
} HashNode;
static HashNode** var_table = NULL;

//
// Function table for .bin functions
//
typedef struct FuncEntry {
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
// Single sequential arena
//
#define ARENA_DEFAULT_SIZE (16 * 1024 * 1024)  // 16 MB default

static char *arena_ptr = NULL;
static size_t arena_size = 0;
static size_t arena_used = 0;

void* arena_alloc_v2(size_t size) {
    if (arena_used + size > arena_size) {
        size_t new_size = arena_size ? arena_size * 2 : ARENA_DEFAULT_SIZE;
        if (new_size < arena_used + size)
            new_size = arena_used + size + ((arena_used + size) / 2);
        char *new_ptr = realloc(arena_ptr, new_size);
        if (!new_ptr) {
            perror("arena realloc failed");
            exit(EXIT_FAILURE);
        }
        arena_ptr = new_ptr;
        arena_size = new_size;
    }
    void *ptr = arena_ptr + arena_used;
    arena_used += size;
    return ptr;
}

static void arena_reset() {
    arena_used = 0;
}

static void arena_free() {
    if (arena_ptr) free(arena_ptr);
    arena_ptr = NULL;
    arena_size = 0;
    arena_used = 0;
}

//
// Pool allocator for VarSlot
//
static VarSlot* pool_alloc() {
    for (int i = 0; i < fixed_top; ++i) {
        if (!fixed_pool[i].in_use) {
            fixed_pool[i].in_use = 1;
            fixed_pool[i].last_use = -1;
            fixed_pool[i].data = NULL;
            fixed_pool[i].value = 0;
            return &fixed_pool[i];
        }
    }
    if (fixed_top < FIXED_VARS) {
        VarSlot* s = &fixed_pool[fixed_top++];
        s->in_use = 1;
        s->last_use = -1;
        s->data = NULL;
        s->value = 0;
        return s;
    }
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        for (int i = 0; i < c->capacity; ++i) {
            if (!c->slots[i].in_use) {
                c->slots[i].in_use = 1;
                c->slots[i].last_use = -1;
                c->slots[i].data = NULL;
                c->slots[i].value = 0;
                return &c->slots[i];
            }
        }
        c = c->next;
    }
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* nc = arena_alloc_v2(sizeof(VarPoolChunk));
    nc->slots = aligned_alloc(CACHE_LINE, cap * sizeof(VarSlot));
    if (!nc->slots) { perror("aligned_alloc slots"); exit(EXIT_FAILURE); }
    nc->capacity = cap;
    nc->next = dynamic_pool;
    dynamic_pool = nc;
    memset(nc->slots, 0, cap * sizeof(VarSlot));
    nc->slots[0].in_use = 1;
    nc->slots[0].last_use = -1;
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
// Optimized .bin loading
//
static void* load_binfunc(const char* name, int* arg_count_out, size_t* len_out) {
    char path[512];
    snprintf(path, sizeof(path), "./funcs/%s.bin", name);
    struct stat st;
    if (stat(path, &st) != 0) {
        if (!strict_mode) return NULL;
        fprintf(stderr, "Error: %s not found\n", path);
        return NULL;
    }
    if (st.st_size < sizeof(BinHeader) + MIN_BIN_SIZE) {
        fprintf(stderr, "Error: %s too small\n", path);
        return NULL;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open bin"); return NULL; }
    BinHeader hdr;
    if (read(fd, &hdr, sizeof(BinHeader)) != (ssize_t)sizeof(BinHeader)) {
        perror("read header");
        close(fd);
        return NULL;
    }
    if (hdr.magic != BIN_MAGIC) {
        fprintf(stderr, "Error: bad magic in %s\n", path);
        close(fd);
        return NULL;
    }
    size_t code_size = st.st_size - sizeof(BinHeader);
    void* mapped = mmap(NULL, code_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, sizeof(BinHeader));
    if (mapped == MAP_FAILED) { perror("mmap"); close(fd); return NULL; }
    uint32_t crc = crc32(0, (unsigned char*)mapped, code_size);
    if (crc != hdr.code_crc) {
        fprintf(stderr, "CRC mismatch %s\n", path);
        munmap(mapped, code_size);
        close(fd);
        return NULL;
    }
    close(fd);
    *arg_count_out = hdr.arg_count;
    *len_out = code_size;
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
        *arg_count_out = -1;
        *len_out = 0;
        return NULL;
    }
    for (int i = 0; i < func_count; ++i) {
        if (strcmp(func_table[i].name, name) == 0) {
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count, &func_table[i].len);
                if (!func_table[i].ptr) {
                    *arg_count_out = -1;
                    *len_out = 0;
                    return NULL;
                }
            }
            *arg_count_out = func_table[i].arg_count < 0 ? -1 : func_table[i].arg_count;
            *len_out = func_table[i].len;
            return func_table[i].ptr;
        }
    }
    *arg_count_out = -1;
    *len_out = 0;
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
// StatementBlock helpers
//
static void block_init(StatementBlock* block) {
    block->stmts = NULL;
    block->count = 0;
    block->capacity = 0;
}

static IRStmt* block_alloc_stmt(StatementBlock* block) {
    if (block->count >= block->capacity) {
        int newc = block->capacity ? block->capacity * 2 : 4;
        IRStmt* tmp = realloc(block->stmts, sizeof(IRStmt) * newc);
        if (!tmp) { perror("realloc block"); exit(EXIT_FAILURE); }
        block->stmts = tmp;
        block->capacity = newc;
    }
    IRStmt* s = &block->stmts[block->count++];
    memset(s, 0, sizeof(IRStmt));
    return s;
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
            return node->index;
        }
        node = node->next;
    }
    VarSlot* s = pool_alloc();
    s->data = strdup(name);
    if (!s->data) { perror("strdup"); exit(EXIT_FAILURE); }
    HashNode* hn = arena_alloc_v2(sizeof(HashNode));
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
    hn->index = var_count;
    env_array[var_count] = s;
    return var_count++;
}

//
// initialize env
//
static void init_env(int total_vars) {
    if (total_vars <= 0) total_vars = FIXED_VARS * 2;
    if (total_vars > (1 << 20)) {
        fprintf(stderr, "Error: FIXED_VARS too large\n");
        exit(EXIT_FAILURE);
    }
    env_alloc_size = total_vars;
    env_array = aligned_alloc(CACHE_LINE, sizeof(VarSlot*) * env_alloc_size);
    if (!env_array) { perror("aligned_alloc env"); exit(EXIT_FAILURE); }
    memset(env_array, 0, sizeof(VarSlot*) * env_alloc_size);
    fixed_pool = aligned_alloc(CACHE_LINE, sizeof(VarSlot) * FIXED_VARS);
    if (!fixed_pool) { perror("aligned_alloc fixed_pool"); exit(EXIT_FAILURE); }
    memset(fixed_pool, 0, sizeof(VarSlot) * FIXED_VARS);
}

//
// Enhanced parser with universal type
//
static int parse_line_v3(const char* line, IR* ir, int line_num);
static int parse_expression_enhanced(const char* expr, int expr_len, IR* nested_ir);
static int parse_enhanced_arguments(const char* args_start, const char* args_end, IRStmt* stmt);
static int parse_inline_block(const char* block_start, const char* block_end, StatementBlock* block);

// Helper to find matching delimiter (handles only () )
static int find_matching_delim(const char* str, int start, char open, char close) {
    int delim_count = 1;
    int pos = start + 1;
    while (str[pos] && delim_count > 0) {
        if (str[pos] == open) delim_count++;
        else if (str[pos] == close) delim_count--;
        pos++;
    }
    return (delim_count == 0) ? pos - 1 : -1;
}

// Helper to check if a string is a numeric literal
static bool is_numeric_literal(const char* str, int len) {
    if (len == 0) return false;
    int i = 0;
    if (str[0] == '-') i++; // Allow negative numbers
    for (; i < len; i++) {
        if (!isdigit((unsigned char)str[i])) return false;
    }
    return true;
}

// Parse inline block of comma-separated statements (newlines allowed for formatting)
static int parse_inline_block(const char* block_start, const char* block_end, StatementBlock* block) {
    block_init(block);

    // Count statements by top-level commas (paren-aware)
    int stmt_count = 0;
    int paren_depth = 0;
    for (const char* p = block_start; p <= block_end; ++p) {
        if (*p == '(') paren_depth++;
        else if (*p == ')') paren_depth--;
        else if (*p == ',' && paren_depth == 0) stmt_count++;
    }
    if (block_start <= block_end) stmt_count++;

    // Parse each statement
    const char* stmt_start = block_start;
    int current_stmt = 0;
    paren_depth = 0;
    for (const char* p = block_start; p <= block_end + 1; ++p) {
        if (p > block_end || (*p == ',' && paren_depth == 0)) {
            const char* stmt_end = (p > block_end) ? block_end : p - 1;
            while (stmt_start <= stmt_end && isspace((unsigned char)*stmt_start)) stmt_start++;
            while (stmt_end >= stmt_start && isspace((unsigned char)*stmt_end)) stmt_end--;
            int stmt_len = (stmt_end >= stmt_start) ? (int)(stmt_end - stmt_start + 1) : 0;

            if (stmt_len > 0) {
                IR nested_ir;
                ir_init(&nested_ir);
                if (parse_expression_enhanced(stmt_start, stmt_len, &nested_ir) == 0 && nested_ir.count > 0) {
                    IRStmt* block_stmt = block_alloc_stmt(block);
                    *block_stmt = nested_ir.stmts[0];
                } else {
                    free(nested_ir.stmts);
                    return -1;
                }
                free(nested_ir.stmts);
            }
            stmt_start = p + 1;
            current_stmt++;
        }
        if (p <= block_end) {
            if (*p == '(') paren_depth++;
            else if (*p == ')') paren_depth--;
        }
    }
    return block->count > 0 ? 0 : -1;
}

// Enhanced argument parsing for universal type (handles inline blocks and newline formatting)
static int parse_enhanced_arguments(const char* args_start, const char* args_end, IRStmt* stmt) {
    // Count arguments by top-level commas (paren-aware)
    int arg_count = 0;
    int paren_depth = 0;
    for (const char* p = args_start; p <= args_end; ++p) {
        if (*p == '(') paren_depth++;
        else if (*p == ')') paren_depth--;
        else if (*p == ',' && paren_depth == 0) arg_count++;
    }
    if (args_start <= args_end) arg_count++;

    // Allocate args array
    stmt->argc = arg_count;
    stmt->args = malloc(sizeof(void*) * arg_count);
    if (!stmt->args) {
        perror("malloc args");
        return -1;
    }
    memset(stmt->args, 0, sizeof(void*) * arg_count);

    // Parse each argument
    int current_arg = 0;
    paren_depth = 0;
    const char* arg_start = args_start;
    for (const char* p = args_start; p <= args_end + 1; ++p) {
        if (p > args_end || (*p == ',' && paren_depth == 0)) {
            const char* arg_end = (p > block_end) ? args_end : p - 1;
            while (arg_start <= arg_end && isspace((unsigned char)*arg_start)) arg_start++;
            while (arg_end >= arg_start && isspace((unsigned char)*arg_end)) arg_end--;
            int arg_len = (arg_end >= arg_start) ? (int)(arg_end - arg_start + 1) : 0;

            if (arg_len <= 0) {
                stmt->args[current_arg] = NULL;
            } else {
                // Check for inline block (contains '=')
                bool is_block = false;
                if (arg_start[0] == '(') {
                    int close_pos = find_matching_delim(arg_start, 0, '(', ')');
                    if (close_pos == arg_len - 1) {
                        int td = 0;
                        for (const char* q = arg_start; q <= arg_end; ++q) {
                            if (*q == '(') td++;
                            else if (*q == ')') td--;
                            else if (*q == '=' && td == 0) {
                                is_block = true;
                                break;
                            }
                        }
                    }
                }

                if (is_block) {
                    // Parse as a StatementBlock
                    StatementBlock* block = arena_alloc_v2(sizeof(StatementBlock));
                    block_init(block);
                    if (parse_inline_block(arg_start + 1, arg_end - 1, block) == 0) {
                        stmt->args[current_arg] = block;
                    } else {
                        free(block->stmts);
                        stmt->args[current_arg] = NULL;
                        return -1;
                    }
                } else {
                    // Check for nested assignment
                    bool has_assignment = false;
                    int td = 0;
                    for (const char* q = arg_start; q <= arg_end; ++q) {
                        if (*q == '(') td++;
                        else if (*q == ')') td--;
                        else if (*q == '=' && td == 0) { has_assignment = true; break; }
                    }

                    if (has_assignment) {
                        // Nested assignment -> parse into a single IRStmt
                        IR nested_ir;
                        ir_init(&nested_ir);
                        if (parse_expression_enhanced(arg_start, arg_len, &nested_ir) == 0 && nested_ir.count > 0) {
                            IRStmt* nested_stmt = arena_alloc_v2(sizeof(IRStmt));
                            *nested_stmt = nested_ir.stmts[0];
                            stmt->args[current_arg] = nested_stmt;
                        } else {
                            free(nested_ir.stmts);
                            stmt->args[current_arg] = NULL;
                            return -1;
                        }
                        free(nested_ir.stmts);
                    } else if (arg_len >= 2 && arg_start[0] == '"' && arg_end[0] == '"') {
                        // String literal
                        char* literal = arena_alloc_v2(arg_len - 1);
                        strncpy(literal, arg_start + 1, arg_len - 2);
                        literal[arg_len - 2] = '\0';
                        stmt->args[current_arg] = literal;
                    } else if (is_numeric_literal(arg_start, arg_len)) {
                        // Numeric literal
                        char temp[arg_len + 1];
                        strncpy(temp, arg_start, arg_len);
                        temp[arg_len] = '\0';
                        long* num = arena_alloc_v2(sizeof(long));
                        *num = atol(temp);
                        stmt->args[current_arg] = num;
                    } else {
                        // Variable
                        char simple_var[MAX_NAME_LEN];
                        if (arg_len < MAX_NAME_LEN) {
                            strncpy(simple_var, arg_start, arg_len);
                            simple_var[arg_len] = '\0';
                            char *s = simple_var;
                            while (*s && isspace((unsigned char)*s)) s++;
                            if (s != simple_var) memmove(simple_var, s, strlen(s) + 1);
                            int idx = var_index(simple_var);
                            stmt->args[current_arg] = env_array[idx];
                        } else {
                            stmt->args[current_arg] = NULL;
                        }
                    }
                }
            }
            current_arg++;
            arg_start = p + 1;
        }
        if (p <= args_end) {
            if (*p == '(') paren_depth++;
            else if (*p == ')') paren_depth--;
        }
    }
    return 0;
}

// Enhanced parse_expression with universal type
static int parse_expression_enhanced(const char* expr, int expr_len, IR* nested_ir) {
    const char* eq = NULL;
    for (int i = 0; i < expr_len; i++) {
        if (expr[i] == '=') {
            eq = expr + i;
            break;
        }
    }
    if (!eq) return -1;
    const char* lhs_start = expr;
    const char* lhs_end = eq - 1;
    while (lhs_start < lhs_end && isspace((unsigned char)*lhs_start)) lhs_start++;
    while (lhs_end > lhs_start && isspace((unsigned char)*lhs_end)) lhs_end--;
    if (lhs_start >= lhs_end) return -1;
    int lhs_len = lhs_end - lhs_start + 1;
    char lhs[MAX_NAME_LEN];
    if (lhs_len >= MAX_NAME_LEN) return -1;
    strncpy(lhs, lhs_start, lhs_len);
    lhs[lhs_len] = '\0';
    const char* rhs = eq + 1;
    while (isspace((unsigned char)*rhs)) rhs++;

    const char* open_delim = strchr(rhs, '(');
    if (!open_delim) return -1;

    /* compute function name (safe) */
    const char* fname_end = open_delim - 1;
    while (fname_end > rhs && isspace((unsigned char)*fname_end)) fname_end--;
    int fname_len = (int)(fname_end - rhs + 1);
    if (fname_len <= 0 || fname_len >= MAX_NAME_LEN) return -1;
    char fname[MAX_NAME_LEN];
    memcpy(fname, rhs, fname_len);
    fname[fname_len] = '\0';

    /* find matching parenthesis */
    int close_pos = find_matching_delim(rhs, (int)(open_delim - rhs), '(', ')');
    if (close_pos < 0) return -1;
    const char* content_start = open_delim + 1;
    const char* content_end = rhs + close_pos - 1;
    while (content_start < content_end && isspace((unsigned char)*content_start)) content_start++;
    while (content_end > content_start && isspace((unsigned char)*content_end)) content_end--;

    IRStmt* stmt = ir_alloc_stmt(nested_ir);
    stmt->lhs_index = var_index(lhs);
    strncpy(stmt->func_name, fname, MAX_NAME_LEN);
    if (content_start < content_end) {
        if (parse_enhanced_arguments(content_start, content_end, stmt) != 0) {
            return -1;
        }
    } else {
        stmt->argc = 0;
        stmt->args = NULL;
    }
    return 0;
}

// Parse line with universal type
static int parse_line_v3(const char* line, IR* ir, int line_num) {
    int len = strlen(line);
    while (len > 0 && isspace((unsigned char)line[len-1])) len--;
    if (len <= 0) return 0;
    if (line[0] == '-' && line[1] == '-') return 0; // Skip comments
    if (parse_expression_enhanced(line, len, ir) != 0) {
        if (strict_mode) {
            fprintf(stderr, "Parse error at line %d: %s\n", line_num, line);
            return -1;
        }
        return 0;
    }
    return 0;
}

// Enhanced executor with universal type
static BinContext global_bin_context;

static void* execute_statement_block(struct BinContext* ctx, StatementBlock* block) {
    if (!ctx || !block || block->count <= 0) return NULL;
    void* last_result = NULL;
    for (int i = 0; i < block->count; i++) {
        IRStmt* stmt = &block->stmts[i];
        if (!stmt->func_ptr && stmt->func_name[0]) {
            size_t len;
            int arg_count;
            stmt->func_ptr = get_func_ptr(stmt->func_name, &arg_count, &len);
        }
        if (!stmt->func_ptr) {
            if (strict_mode) {
                fprintf(stderr, "Error: function '%s' not found\n", stmt->func_name);
                continue;
            }
            continue;
        }
        // Prepare arguments
        void** args = stmt->args;
        for (int j = 0; j < stmt->argc; j++) {
            if (!args[j]) continue;
            if (((IRStmt*)args[j])->lhs_index >= 0) {
                // Nested assignment (IRStmt*)
                IRStmt* nested = (IRStmt*)args[j];
                args[j] = execute_statement_block(ctx, &(StatementBlock){
                    .stmts = nested,
                    .count = 1,
                    .capacity = 1
                });
            } else if (((StatementBlock*)args[j])->stmts) {
                // Inline block (StatementBlock*)
                args[j] = execute_statement_block(ctx, (StatementBlock*)args[j]);
            }
        }
        VarSlot* lhs = (stmt->lhs_index >= 0) ? ctx->env[stmt->lhs_index] : NULL;
        BinFunc fn = (BinFunc)stmt->func_ptr;
        void* result = fn(args, stmt->argc, ctx);
        if (lhs && result) {
            lhs->data = result;
            if (result && is_numeric_literal((char*)result, strlen((char*)result))) {
                lhs->value = *(long*)result;
            }
        }
        last_result = result;
    }
    return last_result;
}

static void executor_enhanced(IRStmt* stmts, int stmt_count, VarSlot** env) {
    if (!stmts || stmt_count <= 0) return;
    global_bin_context.env = env;
    global_bin_context.func_table = func_table;
    global_bin_context.func_count = func_count;
    for (int i = 0; i < stmt_count; ++i) {
        IRStmt* stmt = &stmts[i];
        if (stmt->dead || stmt->lhs_index < 0) continue;
        if (!stmt->func_ptr && stmt->func_name[0]) {
            size_t len;
            int arg_count;
            stmt->func_ptr = get_func_ptr(stmt->func_name, &arg_count, &len);
        }
        if (!stmt->func_ptr) {
            if (strict_mode) {
                fprintf(stderr, "Error: function '%s' not found\n", stmt->func_name);
                exit(EXIT_FAILURE);
            }
            continue;
        }
        // Prepare arguments
        void** args = stmt->args;
        for (int j = 0; j < stmt->argc; j++) {
            if (!args[j]) continue;
            if (((IRStmt*)args[j])->lhs_index >= 0) {
                // Nested assignment (IRStmt*)
                IRStmt* nested = (IRStmt*)args[j];
                args[j] = execute_statement_block(&global_bin_context, &(StatementBlock){
                    .stmts = nested,
                    .count = 1,
                    .capacity = 1
                });
            } else if (((StatementBlock*)args[j])->stmts) {
                // Inline block (StatementBlock*)
                args[j] = execute_statement_block(&global_bin_context, (StatementBlock*)args[j]);
            }
        }
        VarSlot* lhs = env[stmt->lhs_index];
        if (!lhs) continue;
        BinFunc fn = (BinFunc)stmt->func_ptr;
        void* result = fn(args, stmt->argc, &global_bin_context);
        if (result) {
            lhs->data = result;
            if (result && is_numeric_literal((char*)result, strlen((char*)result))) {
                lhs->value = *(long*)result;
            }
        }
    }
}

static void cleanup_all() {
    if (env_array) {
        for (int i = 0; i < var_count; ++i)
            if (env_array[i] && env_array[i].data) free(env_array[i].data);
        free(env_array);
        env_array = NULL;
    }
    if (var_table) {
        for (int i = 0; i < var_table_size; ++i) {
            HashNode* node = var_table[i];
            while (node) {
                HashNode* nx = node->next;
                node = nx;
            }
        }
        free(var_table);
        var_table = NULL;
    }
    if (fixed_pool) { free(fixed_pool); fixed_pool = NULL; }
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        VarPoolChunk* nx = c->next;
        if (c->slots) free(c->slots);
        c = nx;
    }
    dynamic_pool = NULL;
    if (func_table) {
        for (int i = 0; i < func_count; ++i)
            if (func_table[i].ptr && func_table[i].len > 0)
                munmap(func_table[i].ptr, func_table[i].len);
        free(func_table);
        func_table = NULL;
    }
    arena_free();
}

static char* read_block(FILE* f, int *out_lines_read) {
    char *line = NULL;
    size_t lcap = 0;
    ssize_t r;
    size_t bufcap = 4096;
    char *buf = malloc(bufcap);
    if (!buf) { perror("malloc read_block"); exit(EXIT_FAILURE); }
    size_t buflen = 0;
    int depth = 0;
    int lines = 0;
    int have_eq = 0;
    while ((r = getline(&line, &lcap, f)) != -1) {
        lines++;
        if (buflen + (size_t)r + 1 > bufcap) {
            while (buflen + (size_t)r + 1 > bufcap) bufcap *= 2;
            char *nb = realloc(buf, bufcap);
            if (!nb) { perror("realloc read_block"); exit(EXIT_FAILURE); }
            buf = nb;
        }
        memcpy(buf + buflen, line, (size_t)r);
        buflen += (size_t)r;
        buf[buflen] = '\0';
        for (ssize_t i = 0; i < r; ++i) {
            char c = line[i];
            if (c == '(') depth++;
            else if (c == ')') depth--;
            else if (c == '=') have_eq = 1;
        }
        if (depth <= 0 && have_eq) break;
    }
    free(line);
    if (buflen == 0) { free(buf); *out_lines_read = 0; return NULL; }
    *out_lines_read = lines;
    return buf;
}

//
// Script parsing and execution
//
static IR* parse_script_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        perror("fopen script");
        return NULL;
    }
    IR* ir = malloc(sizeof(IR));
    if (!ir) {
        fclose(f);
        perror("malloc IR");
        return NULL;
    }
    ir_init(ir);
    int line_num = 1;
    while (1) {
        int consumed = 0;
        char *block = read_block(f, &consumed);
        if (!block) break;
        if (parse_line_v3(block, ir, line_num) == -1) {
            if (strict_mode) {
                fprintf(stderr, "Parse error in %s at line %d: %s\n", path, line_num, block);
                free(block);
                fclose(f);
                if (ir->stmts) {
                    for (int i = 0; i < ir->count; i++) {
                        if (ir->stmts[i].args) {
                            for (int j = 0; j < ir->stmts[i].argc; j++) {
                                if (ir->stmts[i].args[j] && ((StatementBlock*)ir->stmts[i].args[j])->stmts) {
                                    free(((StatementBlock*)ir->stmts[i].args[j])->stmts);
                                }
                            }
                            free(ir->stmts[i].args);
                        }
                    }
                    free(ir->stmts);
                }
                free(ir);
                return NULL;
            }
        }
        line_num += consumed;
        free(block);
    }
    fclose(f);
    if (ir->count == 0) {
        fprintf(stderr, "Warning: no valid statements in %s\n", path);
        if (ir->stmts) free(ir->stmts);
        free(ir);
        return NULL;
    }
    return ir;
}

static void run_script(const char* path) {
    IR* ir = parse_script_file(path);
    if (!ir) {
        fprintf(stderr, "Error: failed to parse script %s\n", path);
        return;
    }
    executor_enhanced(ir->stmts, ir->count, env_array);
    if (ir->stmts) {
        for (int i = 0; i < ir->count; i++) {
            if (ir->stmts[i].args) {
                for (int j = 0; i < ir->stmts[i].argc; j++) {
                    if (ir->stmts[i].args[j] && ((StatementBlock*)ir->stmts[i].args[j])->stmts) {
                        free(((StatementBlock*)ir->stmts[i].args[j])->stmts);
                    }
                }
                free(ir->stmts[i].args);
            }
        }
        free(ir->stmts);
    }
    free(ir);
}

//
// main
//
int preload_all = 0;
char *preload_list = NULL;

int main(int argc, char **argv) {
    atexit(cleanup_all);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.optivar> [--fixed-vars=N] [--table-size=N] [--preload|--preload=list:bin1,bin2,...] [--strict]\n", argv[0]);
        return 1;
    }
    FIXED_VARS = DEFAULT_FIXED_VARS;
    var_table_size = 4096;
    char *script_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--fixed-vars=", 13) == 0) {
            FIXED_VARS = atoi(argv[i] + 13);
            if (FIXED_VARS <= 0) FIXED_VARS = DEFAULT_FIXED_VARS;
        } else if (strncmp(argv[i], "--table-size=", 13) == 0) {
            var_table_size = atoi(argv[i] + 13);
            if (var_table_size <= 0) {
                var_table_size = 4096;
                fprintf(stderr, "Warning: Invalid table-size, using default 4096\n");
            } else if ((var_table_size & (var_table_size - 1)) != 0) {
                var_table_size = 1 << (32 - __builtin_clz(var_table_size - 1));
                fprintf(stderr, "Warning: table-size rounded to power of two: %d\n", var_table_size);
            }
        } else if (strcmp(argv[i], "--preload") == 0) {
            preload_all = 1;
        } else if (strncmp(argv[i], "--preload=list:", 15) == 0) {
            preload_list = argv[i] + 15;
        } else if (strcmp(argv[i], "--strict") == 0) {
            strict_mode = 1;
        } else if (argv[i][0] != '-') {
            script_path = argv[i];
        }
    }
    if (!script_path) {
        fprintf(stderr, "Error: no script specified\n");
        return 1;
    }
    init_env(FIXED_VARS * 2);
    preload_binfuncs("./funcs");
    if (preload_all) {
        for (int i = 0; i < func_count; i++) {
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(
                    func_table[i].name,
                    &func_table[i].arg_count,
                    &func_table[i].len
                );
            }
        }
    } else if (preload_list) {
        char *list_copy = strdup(preload_list);
        char *token = strtok(list_copy, ",");
        while (token) {
            for (int i = 0; i < func_count; i++) {
                if (strcmp(func_table[i].name, token) == 0 && !func_table[i].ptr) {
                    func_table[i].ptr = load_binfunc(
                        func_table[i].name,
                        &func_table[i].arg_count,
                        &func_table[i].len
                    );
                }
            }
            token = strtok(NULL, ",");
        }
        free(list_copy);
    }
    run_script(script_path);
    return 0;
}
