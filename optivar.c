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
#define FIXED_ARG_POOL 8
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
    void* data;     // either pointer payload or strdup'd name
    int in_use;
    int last_use;
    long value;     // numeric value if needed
    char pad[CACHE_LINE - sizeof(void*) - 2*sizeof(int) - sizeof(long)];
} VarSlot;

// Forward declarations
struct BinContext;
struct IRStmt;
struct StatementBlock;

// Enhanced statement block structure
typedef struct StatementBlock {
    struct IRStmt* stmts;
    int count;
    int capacity;
} StatementBlock;

typedef struct IRStmt {
    int lhs_index;
    void* func_ptr;        // kept for backward compatibility
    int argc;
    int* arg_indices;      // indices into env_array
    int dead;
    char func_name[MAX_NAME_LEN]; // store the function name
    
    // Enhanced nested statement support
    StatementBlock* arg_blocks;    // Array of statement blocks (one per argument)
    int* arg_types;                // 0=simple var, 1=nested assignment, 2=statement block
    
    char pad[CACHE_LINE - 4*sizeof(int) - sizeof(void*) - sizeof(int*) - MAX_NAME_LEN - 
             sizeof(StatementBlock*) - sizeof(int*)];
} IRStmt;

// Add static assertions after type definitions
static_assert(sizeof(VarSlot) % CACHE_LINE == 0, "VarSlot not cache-aligned");
static_assert(sizeof(IRStmt) % CACHE_LINE == 0, "IRStmt not cache-aligned");

// Enhanced bin function signature with context for bin-to-bin calls
typedef void (*BinFunc)(long* lhs, long* args, 
                       StatementBlock* arg_blocks, int argc,
                       struct BinContext* ctx);

// Context passed to bin functions for direct bin-to-bin calls
typedef struct BinContext {
    VarSlot** env;           // Full environment access
    struct FuncEntry* func_table;   // For bin-to-bin calls
    int func_count;
    long* temp_buffer;       // Temporary buffer for arguments
    size_t temp_buffer_size;
} BinContext;

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

static char* arena_ptr = NULL;    // start of buffer
static size_t arena_size = 0;     // total allocated
static size_t arena_used = 0;     // current offset

// ----------------------
// Arena helpers
// ----------------------
#define ARENA_ALIGN 64
static void* arena_alloc(size_t size) {
    size = (size + ARENA_ALIGN - 1) & ~(ARENA_ALIGN - 1); // align
    if (!arena_ptr) {
        arena_size = (size > ARENA_DEFAULT_SIZE) ? size : ARENA_DEFAULT_SIZE;
        arena_ptr = malloc(arena_size);
        if (!arena_ptr) { perror("malloc arena"); exit(EXIT_FAILURE); }
        arena_used = 0;
    }
    if (arena_used + size > arena_size) {
        if (arena_size > SIZE_MAX / 2 || arena_used > SIZE_MAX - size) {
            fprintf(stderr, "Error: arena size overflow\n");
            exit(EXIT_FAILURE);
        }
        size_t new_size = arena_size * 2;
        while (arena_used + size > new_size) {
            if (new_size > SIZE_MAX / 2) {
                fprintf(stderr, "Error: arena size overflow\n");
                exit(EXIT_FAILURE);
            }
            new_size *= 2;
        }
        char* new_ptr = realloc(arena_ptr, new_size);
        if (!new_ptr) { perror("realloc arena"); exit(EXIT_FAILURE); }
        arena_ptr = new_ptr;
        arena_size = new_size;
    }
    void* out = arena_ptr + arena_used;
    arena_used += size;
    return out;
}

// reset arena (does not free buffer, just resets usage)
static void arena_reset() {
    arena_used = 0;
}

// free arena completely
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
    // try fixed pool quickly (no lock; these are global but only allocated at init/parse time
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
    // search dynamic chunks
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
    // create new chunk from thread arena (fast)
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* nc = arena_alloc(sizeof(VarPoolChunk));
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
        if (!strict_mode) {
            return NULL;  // Silently return NULL in non-strict mode
        }
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

    // CRC check in-place
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
        *arg_count_out = -1;  // -1 signals unlimited arguments
        *len_out = 0;
        return NULL;
    }

    for (int i = 0; i < func_count; ++i) {
        if (strcmp(func_table[i].name, name) == 0) {
            // Lazy-load the function if not loaded
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count, &func_table[i].len);
                if (!func_table[i].ptr) {
                    *arg_count_out = -1;
                    *len_out = 0;
                    return NULL;
                }
            }

            // If arg_count is negative (e.g., -1), treat as unlimited
            if (func_table[i].arg_count < 0) {
                *arg_count_out = -1;  // unlimited
            } else {
                *arg_count_out = func_table[i].arg_count;
            }

            *len_out = func_table[i].len;
            return func_table[i].ptr;
        }
    }

    // Function not found
    *arg_count_out = -1;  // unlimited
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
            return node->index;   // O(1) now
        }
        node = node->next;
    }
    // add new var
    VarSlot* s = pool_alloc();
    s->data = strdup(name);
    if (!s->data) { perror("strdup"); exit(EXIT_FAILURE); }
    HashNode* hn = arena_alloc(sizeof(HashNode));
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
    hn->index = var_count;   // store the index directly
    env_array[var_count] = s;
    int idx = var_count++;
    return idx;
}

//
// initialize env
//
static void init_env(int total_vars) {
    if (total_vars <= 0) total_vars = FIXED_VARS * 2;
    if (total_vars > (1 << 20)) {  // Limit to ~1M
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
// Enhanced statement block functions
//
static StatementBlock* create_statement_block() {
    StatementBlock* block = arena_alloc(sizeof(StatementBlock));
    block->stmts = NULL;
    block->count = 0;
    block->capacity = 0;
    return block;
}

static IRStmt* add_stmt_to_block(StatementBlock* block) {
    if (block->count >= block->capacity) {
        int new_cap = block->capacity ? block->capacity * 2 : 8;
        IRStmt* new_stmts = realloc(block->stmts, sizeof(IRStmt) * new_cap);
        if (!new_stmts) { perror("realloc block stmts"); exit(EXIT_FAILURE); }
        block->stmts = new_stmts;
        block->capacity = new_cap;
    }
    IRStmt* stmt = &block->stmts[block->count++];
    memset(stmt, 0, sizeof(IRStmt));
    return stmt;
}

//
// Enhanced parser that supports nested statements and block syntax
//
static int parse_expression_enhanced(const char* expr, int expr_len, IR* nested_ir);
static int parse_enhanced_arguments(const char* args_start, const char* args_end, IRStmt* stmt);
static int parse_argument_block(const char* arg_start, const char* arg_end, StatementBlock* block);

// Helper to find matching delimiter (handles both () and {})
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

// Enhanced argument parsing that handles statement blocks
static int parse_argument_block(const char* arg_start, const char* arg_end, StatementBlock* block) {
    const char* stmt_start = arg_start;
    int paren_depth = 0;
    int brace_depth = 0;
    
    for (const char* p = arg_start; p <= arg_end + 1; p++) {
        if (p <= arg_end) {
            if (*p == '(') paren_depth++;
            else if (*p == ')') paren_depth--;
            else if (*p == '{') brace_depth++;
            else if (*p == '}') brace_depth--;
        }
        
        // Statement separator: comma at depth 0, or end of block
        if ((p > arg_end || (*p == ',' && paren_depth == 0 && brace_depth == 0))) {
            const char* stmt_end = (p > arg_end) ? arg_end : p - 1;
            
            // Trim whitespace
            while (stmt_start < stmt_end && isspace(*stmt_start)) stmt_start++;
            while (stmt_end > stmt_start && isspace(*stmt_end)) stmt_end--;
            
            if (stmt_start <= stmt_end) {
                int stmt_len = stmt_end - stmt_start + 1;
                
                // Create a temporary IR for this statement
                IR temp_ir;
                ir_init(&temp_ir);
                
                if (parse_expression_enhanced(stmt_start, stmt_len, &temp_ir) == 0 && temp_ir.count > 0) {
                    // Add statement to block
                    IRStmt* block_stmt = add_stmt_to_block(block);
                    *block_stmt = temp_ir.stmts[0]; // Copy the statement
                    
                    // Clean up temporary IR structure (but not the copied content)
                    if (temp_ir.stmts) free(temp_ir.stmts);
                }
            }
            
            stmt_start = p + 1;
        }
    }
    
    return block->count;
}

// Enhanced argument parsing for mixed simple/nested/block arguments
static int parse_enhanced_arguments(const char* args_start, const char* args_end, IRStmt* stmt) {
    // Count arguments first
    int arg_count = 0;
    int paren_depth = 0;
    int brace_depth = 0;
    
    for (const char* p = args_start; p <= args_end; p++) {
        if (*p == '(') paren_depth++;
        else if (*p == ')') paren_depth--;
        else if (*p == '{') brace_depth++;
        else if (*p == '}') brace_depth--;
        else if (*p == ',' && paren_depth == 0 && brace_depth == 0) {
            arg_count++;
        }
    }
    if (args_start <= args_end) arg_count++;
    
    // Allocate arrays
    stmt->argc = arg_count;
    stmt->arg_indices = malloc(sizeof(int) * arg_count);
    stmt->arg_types = malloc(sizeof(int) * arg_count);
    stmt->arg_blocks = malloc(sizeof(StatementBlock) * arg_count);
    
    if (!stmt->arg_indices || !stmt->arg_types || !stmt->arg_blocks) {
        perror("malloc enhanced args");
        return -1;
    }
    
    // Initialize
    memset(stmt->arg_blocks, 0, sizeof(StatementBlock) * arg_count);
    
    // Parse each argument
    int current_arg = 0;
    paren_depth = 0;
    brace_depth = 0;
    const char* arg_start = args_start;
    
    for (const char* p = args_start; p <= args_end + 1; p++) {
        if (p <= args_end) {
            if (*p == '(') paren_depth++;
            else if (*p == ')') paren_depth--;
            else if (*p == '{') brace_depth++;
            else if (*p == '}') brace_depth--;
        }
        
        if ((p > args_end || (*p == ',' && paren_depth == 0 && brace_depth == 0)) && current_arg < arg_count) {
            const char* arg_end = (p > args_end) ? args_end : p - 1;
            
            // Trim whitespace
            while (arg_start < arg_end && isspace(*arg_start)) arg_start++;
            while (arg_end > arg_start && isspace(*arg_end)) arg_end--;
            
            int arg_len = arg_end - arg_start + 1;
            
            // Determine argument type
            if (strchr(arg_start, '{') && find_matching_delim(arg_start, strchr(arg_start, '{') - arg_start, '{', '}') >= 0) {
                // Statement block argument
                stmt->arg_types[current_arg] = 2;
                stmt->arg_indices[current_arg] = -1;
                parse_argument_block(arg_start, arg_end, &stmt->arg_blocks[current_arg]);
            } else {
                // Check for nested assignment
                bool has_assignment = false;
                int temp_paren_depth = 0;
                for (const char* q = arg_start; q <= arg_end; q++) {
                    if (*q == '(') temp_paren_depth++;
                    else if (*q == ')') temp_paren_depth--;
                    else if (*q == '=' && temp_paren_depth == 0) {
                        has_assignment = true;
                        break;
                    }
                }
                
                if (has_assignment) {
                    // Nested assignment
                    stmt->arg_types[current_arg] = 1;
                    IR nested_ir;
                    ir_init(&nested_ir);
                    
                    if (parse_expression_enhanced(arg_start, arg_len, &nested_ir) == 0 && nested_ir.count > 0) {
                        stmt->arg_indices[current_arg] = nested_ir.stmts[0].lhs_index;
                        // Store nested statement in block for execution
                        StatementBlock* block = &stmt->arg_blocks[current_arg];
                        block->stmts = malloc(sizeof(IRStmt));
                        block->count = 1;
                        block->capacity = 1;
                        block->stmts[0] = nested_ir.stmts[0];
                    }
                    
                    if (nested_ir.stmts) free(nested_ir.stmts);
                } else {
                    // Simple variable
                    stmt->arg_types[current_arg] = 0;
                    char simple_var[MAX_NAME_LEN];
                    if (arg_len < MAX_NAME_LEN) {
                        strncpy(simple_var, arg_start, arg_len);
                        simple_var[arg_len] = '\0';
                        stmt->arg_indices[current_arg] = var_index(simple_var);
                    }
                }
            }
            
            current_arg++;
            arg_start = p + 1;
        }
    }
    
    return 0;
}

// Enhanced parse_expression with block support
static int parse_expression_enhanced(const char* expr, int expr_len, IR* nested_ir) {
    // Look for assignment pattern: var = func(args) or var = func{block}
    const char* eq = NULL;
    for (int i = 0; i < expr_len; i++) {
        if (expr[i] == '=') {
            eq = expr + i;
            break;
        }
    }
    
    if (!eq) return -1; // Not an assignment
    
    // Parse LHS variable
    const char* lhs_start = expr;
    const char* lhs_end = eq - 1;
    while (lhs_start < lhs_end && isspace(*lhs_start)) lhs_start++;
    while (lhs_end > lhs_start && isspace(*lhs_end)) lhs_end--;
    
    if (lhs_start >= lhs_end) return -1;
    
    int lhs_len = lhs_end - lhs_start + 1;
    char lhs[MAX_NAME_LEN];
    if (lhs_len >= MAX_NAME_LEN) return -1;
    strncpy(lhs, lhs_start, lhs_len);
    lhs[lhs_len] = '\0';
    
    // Find function name and arguments/blocks
    const char* rhs = eq + 1;
    while (isspace(*rhs)) rhs++;
    
    // Look for either parentheses or braces
    const char* open_delim = NULL;
    char close_delim = ')';
    
    const char* paren = strchr(rhs, '(');
    const char* brace = strchr(rhs, '{');
    
    if (paren && (!brace || paren < brace)) {
        open_delim = paren;
        close_delim = ')';
    } else if (brace) {
        open_delim = brace;
        close_delim = '}';
    }
    
    if (!open_delim) return -1;
    
    // Extract function name
    const char* fname_end = open_delim - 1;
    while (fname_end > rhs && isspace(*fname_end)) fname_end--;
    int fname_len = fname_end - rhs + 1;
    if (fname_len <= 0 || fname_len >= MAX_NAME_LEN) return -1;
    
    char fname[MAX_NAME_LEN];
    strncpy(fname, rhs, fname_len);
    fname[fname_len] = '\0';
    
    // Find matching closing delimiter
    int close_pos = find_matching_delim(rhs, open_delim - rhs, *open_delim, close_delim);
    if (close_pos < 0) return -1;
    
    // Parse arguments/blocks
    const char* content_start = open_delim + 1;
    const char* content_end = rhs + close_pos - 1;
    
    // Skip whitespace
    while (content_start < content_end && isspace(*content_start)) content_start++;
    while (content_end > content_start && isspace(*content_end)) content_end--;
    
    // Create IR statement
    IRStmt* stmt = ir_alloc_stmt(nested_ir);
    stmt->lhs_index = var_index(lhs);
    strncpy(stmt->func_name, fname, MAX_NAME_LEN);
    
    if (content_start < content_end) {
        if (close_delim == '}') {
            // Block syntax - parse as statement block
            stmt->argc = 1;
            stmt->arg_indices = malloc(sizeof(int));
            stmt->arg_types = malloc(sizeof(int));
            stmt->arg_blocks = malloc(sizeof(StatementBlock));
            
            stmt->arg_indices[0] = -1; // No simple variable
            stmt->arg_types[0] = 2;    // Statement block
            
            StatementBlock* block = &stmt->arg_blocks[0];
            block->stmts = NULL;
            block->count = 0;
            block->capacity = 0;
            
            parse_argument_block(content_start, content_end, block);
        } else {
            // Parentheses syntax - parse as enhanced arguments
            parse_enhanced_arguments(content_start, content_end, stmt);
        }
    } else {
        stmt->argc = 0;
        stmt->arg_indices = NULL;
        stmt->arg_types = NULL;
        stmt->arg_blocks = NULL;
    }
    
    return 0;
}

// Enhanced parse_line_v3 function
static int parse_line_v3(const char* line, IR* ir, int line_num) {
    const char* p = line;
    while (isspace((unsigned char)*p)) ++p;
    if (*p == '\0' || (p[0] == '-' && p[1] == '-')) return 0;  // Empty or comment

    // Find the closing parenthesis or brace of the function call as end marker
    // Look for assignment pattern first: var = func(args) or var = func{block}
    const char* eq = strchr(p, '=');
    if (!eq) {
        if (strict_mode) {
            fprintf(stderr, "Parse error at line %d: no '=' in assignment: %s\n", line_num, line);
            return -1;
        }
        return 0; // Skip in non-strict mode
    }
    
    // Find the opening delimiter after the '='
    const char* open_paren = strchr(eq + 1, '(');
    const char* open_brace = strchr(eq + 1, '{');
    
    const char* open_delim = NULL;
    char close_delim = ')';
    
    if (open_paren && (!open_brace || open_paren < open_brace)) {
        open_delim = open_paren;
        close_delim = ')';
    } else if (open_brace) {
        open_delim = open_brace;
        close_delim = '}';
    }
    
    if (!open_delim) {
        if (strict_mode) {
            fprintf(stderr, "Parse error at line %d: no '(' or '{' in function call: %s\n", line_num, line);
            return -1;
        }
        return 0; // Skip in non-strict mode
    }
    
    // Find matching closing delimiter
    int close_delim_pos = find_matching_delim(eq + 1, open_delim - (eq + 1), *open_delim, close_delim);
    if (close_delim_pos < 0) {
        if (strict_mode) {
            fprintf(stderr, "Parse error at line %d: unmatched delimiters: %s\n", line_num, line);
            return -1;
        }
        return 0; // Skip in non-strict mode
    }
    
    // Calculate line length up to and including the closing delimiter
    const char* close_delim_ptr = eq + 1 + close_delim_pos;
    int line_len = close_delim_ptr - p + 1;
    
    return parse_expression_enhanced(p, line_len, ir);
}

//
// Enhanced executor with bin-to-bin support and statement block execution
//
static BinContext global_bin_context;
static long* args_buffer = NULL;
static size_t args_buffer_size = 0;

// Helper function for bin functions to call other bin functions
void* optivar_get_func(struct BinContext* ctx, const char* name) {
    if (!ctx || !ctx->func_table) return NULL;
    
    for (int i = 0; i < ctx->func_count; i++) {
        if (strcmp(ctx->func_table[i].name, name) == 0) {
            if (!ctx->func_table[i].ptr) {
                int arg_count;
                size_t len;
                ctx->func_table[i].ptr = load_binfunc(name, &arg_count, &len);
                ctx->func_table[i].arg_count = arg_count;
                ctx->func_table[i].len = len;
            }
            return ctx->func_table[i].ptr;
        }
    }
    return NULL;
}

// Helper function to execute a statement block
static void execute_statement_block(struct BinContext* ctx, StatementBlock* block) {
    if (!ctx || !block || block->count <= 0) return;
    
    for (int i = 0; i < block->count; i++) {
        IRStmt* stmt = &block->stmts[i];
        
        // Resolve function pointer if needed
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
            continue; // Skip missing functions in non-strict mode
        }
        
        // Prepare arguments
        if ((size_t)stmt->argc > ctx->temp_buffer_size) {
            ctx->temp_buffer_size = stmt->argc * 2;
            ctx->temp_buffer = realloc(ctx->temp_buffer, sizeof(long) * ctx->temp_buffer_size);
            if (!ctx->temp_buffer) { perror("realloc temp_buffer"); exit(EXIT_FAILURE); }
        }
        
        for (int j = 0; j < stmt->argc; j++) {
            if (stmt->arg_types && stmt->arg_types[j] == 2) {
                // Execute statement block first
                execute_statement_block(ctx, &stmt->arg_blocks[j]);
            }
            
            int idx = stmt->arg_indices[j];
            ctx->temp_buffer[j] = (idx >= 0 && ctx->env[idx]) ? ctx->env[idx]->value : 0;
        }
        
        // Get LHS variable
        VarSlot* lhs = (stmt->lhs_index >= 0) ? ctx->env[stmt->lhs_index] : NULL;
        if (!lhs) continue;
        
        // Call the bin function
        BinFunc fn = (BinFunc)stmt->func_ptr;
        fn(&lhs->value, 
           (stmt->argc > 0) ? ctx->temp_buffer : NULL,
           stmt->arg_blocks, 
           stmt->argc, 
           ctx);
    }
}

// Helper function for bin functions to execute nested statements
void optivar_execute_stmts(struct BinContext* ctx, StatementBlock* blocks, int count) {
    if (!ctx || !blocks || count <= 0) return;
    
    for (int i = 0; i < count; i++) {
        execute_statement_block(ctx, &blocks[i]);
    }
}

static void executor_enhanced(IRStmt* stmts, int stmt_count, VarSlot** env) {
    if (!stmts || stmt_count <= 0) return;

    // Initialize global bin context
    global_bin_context.env = env;
    global_bin_context.func_table = func_table;
    global_bin_context.func_count = func_count;
    global_bin_context.temp_buffer = NULL;
    global_bin_context.temp_buffer_size = 0;

    // Ensure main args buffer
    if ((size_t)stmt_count * 16 > args_buffer_size) { // Estimate max args needed
        args_buffer_size = stmt_count * 16;
        args_buffer = realloc(args_buffer, sizeof(long) * args_buffer_size);
        if (!args_buffer) { perror("realloc args_buffer"); exit(EXIT_FAILURE); }
    }

    // Execute each top-level statement
    for (int i = 0; i < stmt_count; ++i) {
        IRStmt* stmt = &stmts[i];
        
        if (stmt->dead || stmt->lhs_index < 0) continue;
        
        // Resolve function pointer if needed
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
            continue; // Skip missing functions in non-strict mode
        }

        // Execute nested statement blocks first
        if (stmt->arg_blocks && stmt->arg_types) {
            for (int j = 0; j < stmt->argc; j++) {
                if (stmt->arg_types[j] == 1 || stmt->arg_types[j] == 2) {
                    // Execute nested assignment or statement block
                    execute_statement_block(&global_bin_context, &stmt->arg_blocks[j]);
                }
            }
        }

        // Prepare arguments
        for (int j = 0; j < stmt->argc; ++j) {
            int idx = stmt->arg_indices[j];
            args_buffer[j] = (idx >= 0 && env[idx]) ? env[idx]->value : 0;
        }

        // Get LHS variable
        VarSlot* lhs = env[stmt->lhs_index];
        if (!lhs) continue;

        // Call the bin function with enhanced context
        BinFunc fn = (BinFunc)stmt->func_ptr;
        fn(&lhs->value,
           (stmt->argc > 0) ? args_buffer : NULL,
           stmt->arg_blocks,
           stmt->argc,
           &global_bin_context);
    }
    
    // Cleanup temp buffer
    if (global_bin_context.temp_buffer) {
        free(global_bin_context.temp_buffer);
        global_bin_context.temp_buffer = NULL;
        global_bin_context.temp_buffer_size = 0;
    }
}

static void cleanup_all() {
    // Free environment variables
    if (env_array) {
        for (int i = 0; i < var_count; ++i)
            if (env_array[i] && env_array[i]->data) free(env_array[i]->data);
        free(env_array);
        env_array = NULL;
    }

    // Free variable hash table (nodes only, slots already freed)
    if (var_table) {
        for (int i = 0; i < var_table_size; ++i) {
            HashNode* node = var_table[i];
            while (node) {
                HashNode* nx = node->next;
                // node->slot already freed
                // node->name points into slot->data, already freed
                node = nx;
            }
        }
        free(var_table);
        var_table = NULL;
    }

    // Free fixed pool
    if (fixed_pool) { free(fixed_pool); fixed_pool = NULL; }

    // Free dynamic pool chunks
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        VarPoolChunk* nx = c->next;
        if (c->slots) free(c->slots);
        c = nx;
    }
    dynamic_pool = NULL;

    // Free preloaded .bin functions
    if (func_table) {
        for (int i = 0; i < func_count; ++i)
            if (func_table[i].ptr && func_table[i].len > 0)
                munmap(func_table[i].ptr, func_table[i].len);
        free(func_table);
        func_table = NULL;
    }

    // Free arena memory
    arena_free();

    // Free static executor args buffer
    if (args_buffer) {
        free(args_buffer);
        args_buffer = NULL;
        args_buffer_size = 0;
    }
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
    
    char* line = NULL;
    size_t ls = 0;
    int line_num = 1;
    ssize_t read;
    while ((read = getline(&line, &ls, f)) != -1) {
        if (parse_line_v3(line, ir, line_num) == -1) {
            if (strict_mode) {
                fprintf(stderr, "Parse error in %s at line %d: %s\n", path, line_num, line);
                free(line);
                fclose(f);
                if (ir->stmts) {
                    // Free any allocated arg_blocks, arg_types and arg_indices
                    for (int i = 0; i < ir->count; i++) {
                        if (ir->stmts[i].arg_blocks) {
                            for (int j = 0; j < ir->stmts[i].argc; j++) {
                                if (ir->stmts[i].arg_blocks[j].stmts) {
                                    free(ir->stmts[i].arg_blocks[j].stmts);
                                }
                            }
                            free(ir->stmts[i].arg_blocks);
                        }
                        if (ir->stmts[i].arg_types) free(ir->stmts[i].arg_types);
                        if (ir->stmts[i].arg_indices) free(ir->stmts[i].arg_indices);
                    }
                    free(ir->stmts);
                }
                free(ir);
                return NULL;
            }
            // In non-strict mode, continue parsing
        }
        line_num++;
    }
    if (ferror(f)) {
        fprintf(stderr, "Error reading %s: getline failed\n", path);
        free(line);
        fclose(f);
        if (ir->stmts) {
            for (int i = 0; i < ir->count; i++) {
                if (ir->stmts[i].arg_blocks) {
                    for (int j = 0; j < ir->stmts[i].argc; j++) {
                        if (ir->stmts[i].arg_blocks[j].stmts) {
                            free(ir->stmts[i].arg_blocks[j].stmts);
                        }
                    }
                    free(ir->stmts[i].arg_blocks);
                }
                if (ir->stmts[i].arg_types) free(ir->stmts[i].arg_types);
                if (ir->stmts[i].arg_indices) free(ir->stmts[i].arg_indices);
            }
            free(ir->stmts);
        }
        free(ir);
        return NULL;
    }
    free(line);
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

    // Cleanup IR memory
    if (ir->stmts) {
        for (int i = 0; i < ir->count; i++) {
            if (ir->stmts[i].arg_blocks) {
                for (int j = 0; j < ir->stmts[i].argc; j++) {
                    if (ir->stmts[i].arg_blocks[j].stmts) {
                        free(ir->stmts[i].arg_blocks[j].stmts);
                    }
                }
                free(ir->stmts[i].arg_blocks);
            }
            if (ir->stmts[i].arg_types) free(ir->stmts[i].arg_types);
            if (ir->stmts[i].arg_indices) free(ir->stmts[i].arg_indices);
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
    // Ensure resources are cleaned up on exit
    atexit(cleanup_all);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.optivar> [--fixed-vars=N] [--table-size=N] [--preload|--preload=list:bin1,bin2,...] [--strict]\n", argv[0]);
        return 1;
    }

    // Default config
    FIXED_VARS = DEFAULT_FIXED_VARS;
    var_table_size = 4096;

    char *script_path = NULL;

    // Parse command-line arguments
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
            preload_list = argv[i] + 15; // skip "list:"
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

    // Initialize environment
    init_env(FIXED_VARS * 2);

    // Load function table (names only)
    preload_binfuncs("./funcs");

    // Preload requested bins
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

    // Run the script
    run_script(script_path);

    return 0; // cleanup_all() runs automatically here
}
