// optivar.c -- Enhanced runtime with string escape handling and universal types
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
static int strict_mode = 1;  // Default to strict mode for OPTIVAR syntax

//
// Universal Type System - Safe runtime types
//
typedef enum {
    TYPE_NONE = 0,
    TYPE_STRING,
    TYPE_NUMBER,
    TYPE_STMT,
    TYPE_BLOCK,
    TYPE_LITERAL,
    TYPE_VARIABLE
} ValueType;

typedef struct Value {
    ValueType type;
    union {
        char* str_val;
        long num_val;
        struct IRStmt* stmt_val;
        struct StatementBlock* block_val;
        void* ptr_val;
    };
    int ref_count;  // Reference counting for safe cleanup
    char pad[CACHE_LINE - sizeof(ValueType) - sizeof(void*) - sizeof(int)];
} Value;

//
// Cache-aligned basic types
//
typedef struct VarSlot {
    Value* value;   // Points to Value instead of raw void*
    int in_use;
    int last_use;
    char name[MAX_NAME_LEN];  // Store name directly to avoid dangling pointers
    char pad[CACHE_LINE - sizeof(Value*) - 2*sizeof(int) - MAX_NAME_LEN];
} VarSlot;

// Forward declarations
struct BinContext;
struct IRStmt;
struct StatementBlock;

typedef struct IRStmt {
    int lhs_index;
    void* func_ptr;
    int argc;
    Value** args;      // Array of Value pointers for type safety
    int dead;
    char func_name[MAX_NAME_LEN];
    char pad[CACHE_LINE - 3*sizeof(int) - sizeof(void*) - sizeof(Value**) - MAX_NAME_LEN];
} IRStmt;

// Static assertions for cache alignment
static_assert(sizeof(VarSlot) % CACHE_LINE == 0, "VarSlot not cache-aligned");
static_assert(sizeof(IRStmt) % CACHE_LINE == 0, "IRStmt not cache-aligned");
static_assert(sizeof(Value) % CACHE_LINE == 0, "Value not cache-aligned");

// Enhanced bin function signature with universal type
typedef Value* (*BinFunc)(Value** args, int argc, struct BinContext* ctx);

// Context passed to bin functions
typedef struct BinContext {
    VarSlot** env;
    struct FuncEntry* func_table;
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
// Unlimited Arena - All allocations go through here for no leaks
//
#define ARENA_DEFAULT_SIZE (16 * 1024 * 1024)  // 16 MB default

typedef struct ArenaChunk {
    char* ptr;
    size_t size;
    size_t used;
    struct ArenaChunk* next;
} ArenaChunk;

static ArenaChunk* arena_head = NULL;
static ArenaChunk* arena_current = NULL;

static ArenaChunk* arena_new_chunk(size_t min_size) {
    size_t chunk_size = min_size > ARENA_DEFAULT_SIZE ? min_size * 2 : ARENA_DEFAULT_SIZE;
    ArenaChunk* chunk = malloc(sizeof(ArenaChunk));
    if (!chunk) {
        perror("arena chunk alloc failed");
        exit(EXIT_FAILURE);
    }
    chunk->ptr = malloc(chunk_size);
    if (!chunk->ptr) {
        free(chunk);
        perror("arena chunk memory failed");
        exit(EXIT_FAILURE);
    }
    chunk->size = chunk_size;
    chunk->used = 0;
    chunk->next = NULL;
    return chunk;
}

void* arena_alloc_unlimited(size_t size) {
    // Align to 8 bytes minimum
    size = (size + 7) & ~7;
    
    if (!arena_current || arena_current->used + size > arena_current->size) {
        ArenaChunk* new_chunk = arena_new_chunk(size);
        if (!arena_head) {
            arena_head = arena_current = new_chunk;
        } else {
            arena_current->next = new_chunk;
            arena_current = new_chunk;
        }
    }
    
    void* ptr = arena_current->ptr + arena_current->used;
    arena_current->used += size;
    memset(ptr, 0, size);  // Zero-initialize for safety
    return ptr;
}

static void arena_free_all() {
    ArenaChunk* chunk = arena_head;
    while (chunk) {
        ArenaChunk* next = chunk->next;
        free(chunk->ptr);
        free(chunk);
        chunk = next;
    }
    arena_head = arena_current = NULL;
}

//
// STRING ESCAPE HANDLING SYSTEM
//
static char* process_string_escapes(const char* input, int input_len, int* output_len) {
    if (!input || input_len <= 0) {
        *output_len = 0;
        return NULL;
    }
    
    // Allocate worst-case size (input might not have any escapes)
    char* result = arena_alloc_unlimited(input_len + 1);
    int result_pos = 0;
    int i = 0;
    
    while (i < input_len) {
        if (input[i] == '\\' && i + 1 < input_len) {
            char next_char = input[i + 1];
            switch (next_char) {
                case '"':
                    result[result_pos++] = '"';
                    break;
                case '\\':
                    result[result_pos++] = '\\';
                    break;
                case '=':
                    result[result_pos++] = '=';
                    break;
                case '(':
                    result[result_pos++] = '(';
                    break;
                case ')':
                    result[result_pos++] = ')';
                    break;
                case ',':
                    result[result_pos++] = ',';
                    break;
                case '-':
                    // Handle \-- for comment escape
                    if (i + 2 < input_len && input[i + 2] == '-') {
                        result[result_pos++] = '-';
                        result[result_pos++] = '-';
                        i++; // Skip extra character
                    } else {
                        result[result_pos++] = '-';
                    }
                    break;
                case 'n':
                    result[result_pos++] = '\n';
                    break;
                case 't':
                    result[result_pos++] = '\t';
                    break;
                case 'r':
                    result[result_pos++] = '\r';
                    break;
                default:
                    // Unknown escape sequence - keep the backslash
                    result[result_pos++] = '\\';
                    result[result_pos++] = next_char;
                    break;
            }
            i += 2; // Skip both backslash and escaped character
        } else {
            result[result_pos++] = input[i];
            i++;
        }
    }
    
    result[result_pos] = '\0';
    *output_len = result_pos;
    return result;
}

// Enhanced string literal detection that handles escapes
static bool is_string_literal_with_escapes(const char* str, int len, char** processed_content, int* content_len) {
    if (len < 2 || str[0] != '"' || str[len-1] != '"') {
        *processed_content = NULL;
        *content_len = 0;
        return false;
    }
    
    // Extract content between quotes
    const char* content_start = str + 1;
    int raw_content_len = len - 2;
    
    // Process escapes in the content
    *processed_content = process_string_escapes(content_start, raw_content_len, content_len);
    return true;
}

// Enhanced numeric literal detection
static bool is_numeric_literal_safe(const char* str, int len, long* value) {
    if (len <= 0) return false;
    
    int i = 0;
    bool negative = false;
    
    if (str[0] == '-') {
        negative = true;
        i++;
        if (i >= len) return false; // Just a minus sign
    }
    
    // Must have at least one digit
    if (i >= len || !isdigit((unsigned char)str[i])) return false;
    
    long result = 0;
    for (; i < len; i++) {
        if (!isdigit((unsigned char)str[i])) return false;
        
        // Check for overflow
        if (result > (LONG_MAX - (str[i] - '0')) / 10) {
            return false; // Would overflow
        }
        
        result = result * 10 + (str[i] - '0');
    }
    
    *value = negative ? -result : result;
    return true;
}

// Safe argument parsing that respects string boundaries with escapes
static int find_argument_boundaries_safe(const char* args_str, int args_len, int** boundaries, int* arg_count) {
    *boundaries = arena_alloc_unlimited(sizeof(int) * (args_len + 2)); // Over-allocate
    *arg_count = 0;
    
    int pos = 0;
    int paren_depth = 0;
    bool in_string = false;
    bool escaped = false;
    
    // Skip leading whitespace
    while (pos < args_len && isspace((unsigned char)args_str[pos])) pos++;
    
    if (pos >= args_len) return 0; // Empty arguments
    
    (*boundaries)[(*arg_count)++] = pos; // Start of first argument
    
    while (pos < args_len) {
        char c = args_str[pos];
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == '(') {
                paren_depth++;
            } else if (c == ')') {
                paren_depth--;
            } else if (c == ',' && paren_depth == 0) {
                // End current argument, start next
                (*boundaries)[(*arg_count)++] = pos; // End of current arg
                
                // Skip whitespace after comma
                pos++;
                while (pos < args_len && isspace((unsigned char)args_str[pos])) pos++;
                
                if (pos < args_len) {
                    (*boundaries)[(*arg_count)++] = pos; // Start of next arg
                }
                continue;
            }
        }
        pos++;
    }
    
    if (*arg_count % 2 == 1) {
        (*boundaries)[(*arg_count)++] = args_len; // End of last argument
    }
    
    return *arg_count / 2; // Return number of arguments (each has start and end)
}

//
// Safe Value management with reference counting
//
static Value* value_create(ValueType type) {
    Value* v = arena_alloc_unlimited(sizeof(Value));
    v->type = type;
    v->ref_count = 1;
    return v;
}

static Value* value_create_string(const char* str) {
    Value* v = value_create(TYPE_STRING);
    if (str) {
        size_t len = strlen(str);
        v->str_val = arena_alloc_unlimited(len + 1);
        strcpy(v->str_val, str);
    }
    return v;
}

static Value* value_create_number(long num) {
    Value* v = value_create(TYPE_NUMBER);
    v->num_val = num;
    return v;
}

static Value* value_create_stmt(IRStmt* stmt) {
    Value* v = value_create(TYPE_STMT);
    v->stmt_val = stmt;
    return v;
}

static Value* value_create_block(StatementBlock* block) {
    Value* v = value_create(TYPE_BLOCK);
    v->block_val = block;
    return v;
}

// Create a literal Value from a string with escape processing
static Value* value_create_literal(const char* literal_str, int literal_len) {
    char* processed_content;
    int content_len;
    
    // Try string literal first
    if (is_string_literal_with_escapes(literal_str, literal_len, &processed_content, &content_len)) {
        Value* v = value_create(TYPE_STRING);
        if (processed_content) {
            v->str_val = arena_alloc_unlimited(content_len + 1);
            strcpy(v->str_val, processed_content);
        } else {
            v->str_val = arena_alloc_unlimited(1);
            v->str_val[0] = '\0';
        }
        return v;
    }
    
    // Try numeric literal
    long num_value;
    if (is_numeric_literal_safe(literal_str, literal_len, &num_value)) {
        return value_create_number(num_value);
    }
    
    // Default to string (variable name or other)
    Value* v = value_create(TYPE_STRING);
    v->str_val = arena_alloc_unlimited(literal_len + 1);
    strncpy(v->str_val, literal_str, literal_len);
    v->str_val[literal_len] = '\0';
    return v;
}

static void value_retain(Value* v) {
    if (v) v->ref_count++;
}

static void value_release(Value* v) {
    if (!v) return;
    v->ref_count--;
    // Note: We don't free arena memory, it's all cleaned up at exit
    // This prevents use-after-free bugs
}

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
    char name[MAX_NAME_LEN];  // Copy name instead of pointer for safety
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
// Safe pool allocator for VarSlot
//
static VarSlot* pool_alloc() {
    for (int i = 0; i < fixed_top; ++i) {
        if (!fixed_pool[i].in_use) {
            fixed_pool[i].in_use = 1;
            fixed_pool[i].last_use = -1;
            fixed_pool[i].value = NULL;
            memset(fixed_pool[i].name, 0, MAX_NAME_LEN);
            return &fixed_pool[i];
        }
    }
    if (fixed_top < FIXED_VARS) {
        VarSlot* s = &fixed_pool[fixed_top++];
        s->in_use = 1;
        s->last_use = -1;
        s->value = NULL;
        memset(s->name, 0, MAX_NAME_LEN);
        return s;
    }
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        for (int i = 0; i < c->capacity; ++i) {
            if (!c->slots[i].in_use) {
                c->slots[i].in_use = 1;
                c->slots[i].last_use = -1;
                c->slots[i].value = NULL;
                memset(c->slots[i].name, 0, MAX_NAME_LEN);
                return &c->slots[i];
            }
        }
        c = c->next;
    }
    int cap = VAR_CHUNK_SIZE;
    VarPoolChunk* nc = arena_alloc_unlimited(sizeof(VarPoolChunk));
    nc->slots = arena_alloc_unlimited(cap * sizeof(VarSlot));
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
// Optimized .bin loading (unchanged)
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
// Preload functions in directory (unchanged)
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
// Safe IR helpers - unlimited allocation
//
static void ir_init(IR* ir) { 
    ir->stmts = NULL; 
    ir->count = ir->capacity = 0; 
}

static IRStmt* ir_alloc_stmt(IR* ir) {
    if (ir->count >= ir->capacity) {
        int newc = ir->capacity ? ir->capacity * 2 : 16;
        IRStmt* tmp = arena_alloc_unlimited(sizeof(IRStmt) * newc);  // Use arena for no leaks
        if (ir->stmts) {
            memcpy(tmp, ir->stmts, sizeof(IRStmt) * ir->count);
        }
        ir->stmts = tmp;
        ir->capacity = newc;
    }
    IRStmt* s = &ir->stmts[ir->count++];
    memset(s, 0, sizeof(IRStmt));
    return s;
}

//
// Safe StatementBlock helpers
//
static void block_init(StatementBlock* block) {
    block->stmts = NULL;
    block->count = 0;
    block->capacity = 0;
}

static IRStmt* block_alloc_stmt(StatementBlock* block) {
    if (block->count >= block->capacity) {
        int newc = block->capacity ? block->capacity * 2 : 4;
        IRStmt* tmp = arena_alloc_unlimited(sizeof(IRStmt) * newc);  // Use arena
        if (block->stmts) {
            memcpy(tmp, block->stmts, sizeof(IRStmt) * block->count);
        }
        block->stmts = tmp;
        block->capacity = newc;
    }
    IRStmt* s = &block->stmts[block->count++];
    memset(s, 0, sizeof(IRStmt));
    return s;
}

//
// Safe var table grow (rebuild)
//
static void grow_var_table() {
    int new_size = var_table_size * 2;
    HashNode** nt = arena_alloc_unlimited(sizeof(HashNode*) * new_size);  // Use arena
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
    var_table = nt;  // No free() - arena handles cleanup
    var_table_size = new_size;
}

static int var_index(const char* name) {
    if (!var_table) {
        var_table = arena_alloc_unlimited(sizeof(HashNode*) * var_table_size);
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
    strncpy(s->name, name, MAX_NAME_LEN - 1);  // Safe copy into slot
    s->name[MAX_NAME_LEN - 1] = '\0';
    
    HashNode* hn = arena_alloc_unlimited(sizeof(HashNode));
    hn->slot = s;
    strncpy(hn->name, name, MAX_NAME_LEN - 1);  // Safe copy
    hn->name[MAX_NAME_LEN - 1] = '\0';
    hn->next = var_table[h];
    var_table[h] = hn;
    
    if (var_count >= env_alloc_size) {
        int ns = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
        VarSlot** ne = arena_alloc_unlimited(sizeof(VarSlot*) * ns);  // Use arena
        if (env_array) {
            memcpy(ne, env_array, sizeof(VarSlot*) * var_count);
        }
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
    env_array = arena_alloc_unlimited(sizeof(VarSlot*) * env_alloc_size);
    
    fixed_pool = arena_alloc_unlimited(sizeof(VarSlot) * FIXED_VARS);
    memset(fixed_pool, 0, sizeof(VarSlot) * FIXED_VARS);
}

//
// ENHANCED OPTIVAR SYNTAX VALIDATION HELPERS WITH ESCAPE SUPPORT
//

// Helper to validate that a string represents a valid function call (contains parentheses)
static bool is_valid_function_call_with_escapes(const char* str, int len) {
    if (len <= 2) return false; // Must have at least "f()"
    
    // Find opening parenthesis (outside of strings)
    const char* open_paren = NULL;
    bool in_string = false;
    bool escaped = false;
    
    for (int i = 0; i < len; i++) {
        char c = str[i];
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == '(') {
                open_paren = str + i;
                break;
            }
        }
    }
    
    if (!open_paren || open_paren == str) return false; // No paren or starts with paren
    
    // Must end with closing parenthesis (outside strings)
    in_string = false;
    escaped = false;
    bool found_close = false;
    
    for (int i = len - 1; i >= 0; i--) {
        char c = str[i];
        
        if (in_string) {
            if (c == '"' && (i == 0 || str[i-1] != '\\')) {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == ')') {
                found_close = true;
                break;
            }
        }
    }
    
    if (!found_close) return false;
    
    // Validate function name (before opening paren)
    for (const char* p = str; p < open_paren; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    }
    
    return true;
}

// Helper to check if a string is a bare variable name (no function call) with escape awareness
static bool is_bare_variable_with_escapes(const char* str, int len) {
    if (len <= 0) return false;
    
    bool in_string = false;
    bool escaped = false;
    
    // Check if it's a valid identifier without parentheses
    for (int i = 0; i < len; i++) {
        char c = str[i];
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == '(' || c == ')') {
                return false; // Has parentheses, so it's a function call
            } else if (!isalnum((unsigned char)c) && c != '_') {
                return false; // Invalid identifier char
            }
        }
    }
    return true;
}

// Helper to check if a string is a bare literal (number or string) with escape support
static bool is_bare_literal_with_escapes(const char* str, int len) {
    if (len <= 0) return false;
    
    // Check for string literal with proper escape handling
    char* processed_content;
    int content_len;
    if (is_string_literal_with_escapes(str, len, &processed_content, &content_len)) {
        return true;
    }
    
    // Check for numeric literal
    long dummy;
    return is_numeric_literal_safe(str, len, &dummy);
}

// Enhanced comment-aware parsing helpers with escape support
static bool is_comment_line_with_escapes(const char* str) {
    bool in_string = false;
    bool escaped = false;
    
    for (const char* p = str; *p; p++) {
        char c = *p;
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (isspace((unsigned char)c)) {
                continue; // Skip whitespace
            } else if (c == '-' && *(p+1) == '-') {
                return true; // Found comment outside string
            } else {
                return false; // Found non-comment content
            }
        }
    }
    return false;
}

static int skip_comments_and_whitespace_with_escapes(const char* str, int len, int* pos) {
    while (*pos < len) {
        char c = str[*pos];
        if (isspace((unsigned char)c)) {
            (*pos)++;
            continue;
        }
        
        // Check for -- comments (but not inside strings)
        if (*pos < len - 1 && c == '-' && str[*pos + 1] == '-') {
            // Verify we're not inside a string
            bool in_string = false;
            bool escaped = false;
            
            for (int i = 0; i < *pos; i++) {
                char prev_c = str[i];
                if (in_string) {
                    if (escaped) {
                        escaped = false;
                    } else if (prev_c == '\\') {
                        escaped = true;
                    } else if (prev_c == '"') {
                        in_string = false;
                    }
                } else {
                    if (prev_c == '"') {
                        in_string = true;
                    }
                }
            }
            
            if (!in_string) {
                // Skip to end of line or string
                while (*pos < len && str[*pos] != '\n') (*pos)++;
                if (*pos < len) (*pos)++; // Skip newline
                continue;
            }
        }
        break;
    }
    return *pos < len;
}

//
// Enhanced parser with escape support
//
static int parse_line_strict_with_escapes(const char* line, IR* ir, int line_num);
static int parse_expression_strict_with_escapes(const char* expr, int expr_len, IR* nested_ir);
static int parse_strict_arguments_with_escapes(const char* args_start, const char* args_end, IRStmt* stmt);
static int parse_inline_block_strict_with_escapes(const char* block_start, const char* block_end, StatementBlock* block);

// Helper to find matching delimiter with escape and comment awareness
static int find_matching_delim_with_escapes(const char* str, int start, char open, char close) {
    int delim_count = 1;
    int pos = start + 1;
    bool in_string = false;
    bool escaped = false;
    
    while (pos < strlen(str) && delim_count > 0) {
        char c = str[pos];
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            // Skip comments
            if (!skip_comments_and_whitespace_with_escapes(str, strlen(str), &pos)) break;
            if (pos >= strlen(str)) break;
            
            c = str[pos];
            if (c == '"') {
                in_string = true;
            } else if (c == open) {
                delim_count++;
            } else if (c == close) {
                delim_count--;
            }
        }
        pos++;
    }
    return (delim_count == 0) ? pos - 1 : -1;
}

// Parse inline block with escape and comment support
static int parse_inline_block_strict_with_escapes(const char* block_start, const char* block_end, StatementBlock* block) {
    block_init(block);
    int block_len = block_end - block_start + 1;

    // Use safe boundary detection
    int* boundaries;
    int boundary_count;
    int arg_count = find_argument_boundaries_safe(block_start, block_len, &boundaries, &boundary_count);
    
    // Parse each statement
    for (int i = 0; i < arg_count; i++) {
        int start_idx = boundaries[i * 2];
        int end_idx = boundaries[i * 2 + 1] - 1;
        
        if (start_idx <= end_idx) {
            const char* stmt_start = block_start + start_idx;
            int stmt_len = end_idx - start_idx + 1;
            
            // Skip empty statements
            while (stmt_len > 0 && isspace((unsigned char)*stmt_start)) {
                stmt_start++;
                stmt_len--;
            }
            while (stmt_len > 0 && isspace((unsigned char)stmt_start[stmt_len-1])) {
                stmt_len--;
            }
            
            if (stmt_len > 0) {
                IR nested_ir;
                ir_init(&nested_ir);
                if (parse_expression_strict_with_escapes(stmt_start, stmt_len, &nested_ir) == 0 && nested_ir.count > 0) {
                    IRStmt* block_stmt = block_alloc_stmt(block);
                    *block_stmt = nested_ir.stmts[0];
                } else {
                    return -1;
                }
            }
        }
    }
    return block->count > 0 ? 0 : -1;
}

// Safe argument parsing with escape support and type safety
static int parse_strict_arguments_with_escapes(const char* args_start, const char* args_end, IRStmt* stmt) {
    int args_len = args_end - args_start + 1;
    
    // Use safe boundary detection
    int* boundaries;
    int boundary_count;
    int arg_count = find_argument_boundaries_safe(args_start, args_len, &boundaries, &boundary_count);
    
    // Allocate args array with proper type safety
    stmt->argc = arg_count;
    if (arg_count > 0) {
        stmt->args = arena_alloc_unlimited(sizeof(Value*) * arg_count);
    } else {
        stmt->args = NULL;
        return 0;
    }

    // Parse each argument
    for (int i = 0; i < arg_count; i++) {
        int start_idx = boundaries[i * 2];
        int end_idx = boundaries[i * 2 + 1] - 1;
        
        if (start_idx > end_idx) {
            fprintf(stderr, "Error: Empty argument not allowed in strict OPTIVAR mode\n");
            return -1;
        }
        
        const char* arg_start = args_start + start_idx;
        int arg_len = end_idx - start_idx + 1;
        
        // Skip whitespace
        while (arg_len > 0 && isspace((unsigned char)*arg_start)) {
            arg_start++;
            arg_len--;
        }
        while (arg_len > 0 && isspace((unsigned char)arg_start[arg_len-1])) {
            arg_len--;
        }
        
        if (arg_len <= 0) {
            fprintf(stderr, "Error: Empty argument not allowed in strict OPTIVAR mode\n");
            return -1;
        }

        // STRICT RULE: All arguments must follow "arg_var = func(...)" pattern
        const char* eq_pos = NULL;
        bool in_string = false;
        bool escaped = false;
        int paren_depth = 0;
        
        for (int j = 0; j < arg_len; j++) {
            char c = arg_start[j];
            
            if (in_string) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    in_string = false;
                }
            } else {
                if (c == '"') {
                    in_string = true;
                } else if (c == '(') {
                    paren_depth++;
                } else if (c == ')') {
                    paren_depth--;
                } else if (c == '=' && paren_depth == 0) {
                    eq_pos = arg_start + j;
                    break;
                }
            }
        }
        
        if (!eq_pos) {
            char temp_arg[arg_len + 1];
            strncpy(temp_arg, arg_start, arg_len);
            temp_arg[arg_len] = '\0';
            fprintf(stderr, "Error: Argument must follow 'var = func(...)' pattern: '%s'\n", temp_arg);
            return -1;
        }

        // Parse the assignment within the argument
        const char* arg_var_start = arg_start;
        const char* arg_var_end = eq_pos - 1;
        while (arg_var_start <= arg_var_end && isspace((unsigned char)*arg_var_start)) arg_var_start++;
        while (arg_var_end >= arg_var_start && isspace((unsigned char)*arg_var_end)) arg_var_end--;
        
        const char* arg_func_start = eq_pos + 1;
        const char* arg_func_end = arg_start + arg_len - 1;
        while (arg_func_start <= arg_func_end && isspace((unsigned char)*arg_func_start)) arg_func_start++;
        while (arg_func_end >= arg_func_start && isspace((unsigned char)*arg_func_end)) arg_func_end--;
        
        int arg_var_len = (arg_var_end >= arg_var_start) ? (int)(arg_var_end - arg_var_start + 1) : 0;
        int arg_func_len = (arg_func_end >= arg_func_start) ? (int)(arg_func_end - arg_func_start + 1) : 0;
        
        if (arg_var_len <= 0) {
            fprintf(stderr, "Error: Missing variable name in argument assignment\n");
            return -1;
        }
        
        if (arg_func_len <= 0) {
            fprintf(stderr, "Error: Missing function call in argument assignment\n");
            return -1;
        }
        
        // Validate that RHS is a function call with escape support
        if (!is_valid_function_call_with_escapes(arg_func_start, arg_func_len)) {
            char temp_func[arg_func_len + 1];
            strncpy(temp_func, arg_func_start, arg_func_len);
            temp_func[arg_func_len] = '\0';
            fprintf(stderr, "Error: RHS must be a function call, got: '%s'\n", temp_func);
            return -1;
        }
        
        // Parse as nested assignment with safe allocation
        IR nested_ir;
        ir_init(&nested_ir);
        
        // Reconstruct the full assignment for parsing
        char* full_assign = arena_alloc_unlimited(arg_len + 1);
        strncpy(full_assign, arg_start, arg_len);
        full_assign[arg_len] = '\0';
        
        if (parse_expression_strict_with_escapes(full_assign, arg_len, &nested_ir) == 0 && nested_ir.count > 0) {
            IRStmt* nested_stmt = arena_alloc_unlimited(sizeof(IRStmt));
            *nested_stmt = nested_ir.stmts[0];
            stmt->args[i] = value_create_stmt(nested_stmt);
        } else {
            return -1;
        }
    }
    return 0;
}

// Strict expression parsing with escape support and type safety
static int parse_expression_strict_with_escapes(const char* expr, int expr_len, IR* nested_ir) {
    // Skip comments at the beginning
    int pos = 0;
    if (!skip_comments_and_whitespace_with_escapes(expr, expr_len, &pos)) {
        return -1; // Empty expression after removing comments
    }
    
    // Find the assignment operator (outside strings)
    const char* eq = NULL;
    bool in_string = false;
    bool escaped = false;
    
    for (int i = pos; i < expr_len; i++) {
        char c = expr[i];
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == '=') {
                eq = expr + i;
                break;
            }
        }
    }
    
    if (!eq) {
        fprintf(stderr, "Error: Expression must contain assignment operator '='\n");
        return -1;
    }

    // Parse LHS (variable name)
    const char* lhs_start = expr + pos;
    const char* lhs_end = eq - 1;
    while (lhs_start < lhs_end && isspace((unsigned char)*lhs_start)) lhs_start++;
    while (lhs_end > lhs_start && isspace((unsigned char)*lhs_end)) lhs_end--;
    
    if (lhs_start >= lhs_end) {
        fprintf(stderr, "Error: Missing variable name on left side of assignment\n");
        return -1;
    }
    
    int lhs_len = lhs_end - lhs_start + 1;
    if (lhs_len >= MAX_NAME_LEN) {
        fprintf(stderr, "Error: Variable name too long (max %d characters)\n", MAX_NAME_LEN - 1);
        return -1;
    }
    
    char lhs[MAX_NAME_LEN];
    strncpy(lhs, lhs_start, lhs_len);
    lhs[lhs_len] = '\0';

    // Validate LHS is a valid variable name (no function calls) with escape support
    if (!is_bare_variable_with_escapes(lhs, lhs_len)) {
        fprintf(stderr, "Error: Left side of assignment must be a simple variable name: '%s'\n", lhs);
        return -1;
    }

    // Parse RHS with escape and comment awareness
    const char* rhs_start = eq + 1;
    pos = rhs_start - expr;
    if (!skip_comments_and_whitespace_with_escapes(expr, expr_len, &pos)) {
        fprintf(stderr, "Error: Missing function call on right side of assignment\n");
        return -1;
    }
    rhs_start = expr + pos;
    
    const char* rhs_end = expr + expr_len - 1;
    while (rhs_end > rhs_start && isspace((unsigned char)*rhs_end)) rhs_end--;
    
    if (rhs_start > rhs_end) {
        fprintf(stderr, "Error: Missing function call on right side of assignment\n");
        return -1;
    }
    
    int rhs_len = rhs_end - rhs_start + 1;
    
    // STRICT RULE: Check for invalid patterns on RHS with escape support
    
    // 1. No bare variables (z = x is invalid)
    if (is_bare_variable_with_escapes(rhs_start, rhs_len)) {
        char temp_rhs[rhs_len + 1];
        strncpy(temp_rhs, rhs_start, rhs_len);
        temp_rhs[rhs_len] = '\0';
        fprintf(stderr, "Error: Variable-to-variable assignment not allowed: %s = %s\n", lhs, temp_rhs);
        return -1;
    }
    
    // 2. No bare literals with escape support (x = "string with \"quotes\"" is invalid, must be x = equal("string with \"quotes\""))
    if (is_bare_literal_with_escapes(rhs_start, rhs_len)) {
        char temp_rhs[rhs_len + 1];
        strncpy(temp_rhs, rhs_start, rhs_len);
        temp_rhs[rhs_len] = '\0';
        fprintf(stderr, "Error: Bare literals not allowed, must wrap in function: %s = %s should be %s = equal(%s)\n", 
                lhs, temp_rhs, lhs, temp_rhs);
        return -1;
    }
    
    // 3. Must be a valid function call with escape support
    if (!is_valid_function_call_with_escapes(rhs_start, rhs_len)) {
        char temp_rhs[rhs_len + 1];
        strncpy(temp_rhs, rhs_start, rhs_len);
        temp_rhs[rhs_len] = '\0';
        fprintf(stderr, "Error: Right side must be a function call: '%s'\n", temp_rhs);
        return -1;
    }

    // Extract function name (outside strings)
    const char* open_delim = NULL;
    in_string = false;
    escaped = false;
    
    for (const char* p = rhs_start; p <= rhs_end; p++) {
        char c = *p;
        
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == '(') {
                open_delim = p;
                break;
            }
        }
    }
    
    if (!open_delim) {
        fprintf(stderr, "Error: Invalid function call syntax\n");
        return -1;
    }
    
    const char* fname_end = open_delim - 1;
    while (fname_end > rhs_start && isspace((unsigned char)*fname_end)) fname_end--;
    int fname_len = (int)(fname_end - rhs_start + 1);
    
    if (fname_len <= 0 || fname_len >= MAX_NAME_LEN) {
        fprintf(stderr, "Error: Invalid function name length\n");
        return -1;
    }
    
    char fname[MAX_NAME_LEN];
    memcpy(fname, rhs_start, fname_len);
    fname[fname_len] = '\0';

    // Find matching parenthesis with escape and comment awareness
    int close_pos = find_matching_delim_with_escapes(rhs_start, (int)(open_delim - rhs_start), '(', ')');
    if (close_pos < 0) {
        fprintf(stderr, "Error: Unmatched parentheses in function call\n");
        return -1;
    }
    
    const char* content_start = open_delim + 1;
    const char* content_end = rhs_start + close_pos - 1;
    
    // Skip comments in function arguments
    pos = content_start - rhs_start;
    if (skip_comments_and_whitespace_with_escapes(rhs_start, close_pos, &pos)) {
        content_start = rhs_start + pos;
    }
    
    while (content_end > content_start && isspace((unsigned char)*content_end)) content_end--;

    // Create the statement with safe allocation
    IRStmt* stmt = ir_alloc_stmt(nested_ir);
    stmt->lhs_index = var_index(lhs);
    strncpy(stmt->func_name, fname, MAX_NAME_LEN - 1);
    stmt->func_name[MAX_NAME_LEN - 1] = '\0';
    
    // Parse arguments with strict validation, escape support, and type safety
    if (content_start <= content_end) {
        if (parse_strict_arguments_with_escapes(content_start, content_end, stmt) != 0) {
            return -1;
        }
    } else {
        stmt->argc = 0;
        stmt->args = NULL;
    }
    
    return 0;
}

// Parse line with strict OPTIVAR validation, escape support, and comment support
static int parse_line_strict_with_escapes(const char* line, IR* ir, int line_num) {
    int len = strlen(line);
    while (len > 0 && isspace((unsigned char)line[len-1])) len--;
    if (len <= 0) return 0;
    if (is_comment_line_with_escapes(line)) return 0; // Skip comment lines
    
    if (parse_expression_strict_with_escapes(line, len, ir) != 0) {
        fprintf(stderr, "Parse error at line %d: %s\n", line_num, line);
        return -1;
    }
    return 0;
}

// Enhanced executor with universal type safety (unchanged)
static BinContext global_bin_context;

static Value* execute_statement_block(struct BinContext* ctx, StatementBlock* block) {
    if (!ctx || !block || block->count <= 0) return NULL;
    Value* last_result = NULL;
    
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
        
        // Prepare arguments with type safety
        Value** args = stmt->args;
        for (int j = 0; j < stmt->argc; j++) {
            if (!args[j]) continue;
            
            if (args[j]->type == TYPE_STMT) {
                // Nested assignment - execute it
                IRStmt* nested = args[j]->stmt_val;
                StatementBlock temp_block = {
                    .stmts = nested,
                    .count = 1,
                    .capacity = 1
                };
                Value* result = execute_statement_block(ctx, &temp_block);
                value_release(args[j]);
                args[j] = result;
                value_retain(args[j]);
            } else if (args[j]->type == TYPE_BLOCK) {
                // Inline block - execute it
                Value* result = execute_statement_block(ctx, args[j]->block_val);
                value_release(args[j]);
                args[j] = result;
                value_retain(args[j]);
            }
        }
        
        VarSlot* lhs = (stmt->lhs_index >= 0) ? ctx->env[stmt->lhs_index] : NULL;
        BinFunc fn = (BinFunc)stmt->func_ptr;
        Value* result = fn(args, stmt->argc, ctx);
        
        if (lhs && result) {
            if (lhs->value) value_release(lhs->value);
            lhs->value = result;
            value_retain(result);
        }
        
        if (last_result) value_release(last_result);
        last_result = result;
        if (last_result) value_retain(last_result);
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
        
        // Prepare arguments with type safety
        Value** args = stmt->args;
        for (int j = 0; j < stmt->argc; j++) {
            if (!args[j]) continue;
            
            if (args[j]->type == TYPE_STMT) {
                // Nested assignment - execute it
                IRStmt* nested = args[j]->stmt_val;
                StatementBlock temp_block = {
                    .stmts = nested,
                    .count = 1,
                    .capacity = 1
                };
                Value* result = execute_statement_block(&global_bin_context, &temp_block);
                value_release(args[j]);
                args[j] = result;
                value_retain(args[j]);
            } else if (args[j]->type == TYPE_BLOCK) {
                // Inline block - execute it
                Value* result = execute_statement_block(&global_bin_context, args[j]->block_val);
                value_release(args[j]);
                args[j] = result;
                value_retain(args[j]);
            }
        }
        
        VarSlot* lhs = env[stmt->lhs_index];
        if (!lhs) continue;
        
        BinFunc fn = (BinFunc)stmt->func_ptr;
        Value* result = fn(args, stmt->argc, &global_bin_context);
        
        if (result) {
            if (lhs->value) value_release(lhs->value);
            lhs->value = result;
            value_retain(result);
        }
    }
}

static void cleanup_all() {
    // Release all variable values
    if (env_array) {
        for (int i = 0; i < var_count; ++i) {
            if (env_array[i] && env_array[i]->value) {
                value_release(env_array[i]->value);
            }
        }
    }
    
    // Cleanup mapped functions
    if (func_table) {
        for (int i = 0; i < func_count; ++i) {
            if (func_table[i].ptr && func_table[i].len > 0) {
                munmap(func_table[i].ptr, func_table[i].len);
            }
        }
        free(func_table);
        func_table = NULL;
    }
    
    // Arena cleanup handles everything else automatically
    arena_free_all();
    
    // Clear global state
    env_array = NULL;
    var_table = NULL;
    fixed_pool = NULL;
    dynamic_pool = NULL;
    var_count = 0;
    fixed_top = 0;
}

static char* read_block_with_comments_and_escapes(FILE* f, int *out_lines_read) {
    char *line = NULL;
    size_t lcap = 0;
    ssize_t r;
    size_t bufcap = 4096;
    char *buf = arena_alloc_unlimited(bufcap);  // Use arena for safe allocation
    size_t buflen = 0;
    int depth = 0;
    int lines = 0;
    int have_eq = 0;
    
    while ((r = getline(&line, &lcap, f)) != -1) {
        lines++;
        
        // Skip pure comment lines with escape awareness
        if (is_comment_line_with_escapes(line)) {
            continue;
        }
        
        if (buflen + (size_t)r + 1 > bufcap) {
            while (buflen + (size_t)r + 1 > bufcap) bufcap *= 2;
            char *nb = arena_alloc_unlimited(bufcap);  // Use arena
            memcpy(nb, buf, buflen);
            buf = nb;
        }
        memcpy(buf + buflen, line, (size_t)r);
        buflen += (size_t)r;
        buf[buflen] = '\0';
        
        // Count parentheses with escape awareness, ignoring comments
        bool in_comment = false;
        bool in_string = false;
        bool escaped = false;
        
        for (ssize_t i = 0; i < r; ++i) {
            char c = line[i];
            
            if (in_string) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    in_string = false;
                }
                continue;
            }
            
            if (!in_comment && i < r - 1 && c == '-' && line[i+1] == '-') {
                in_comment = true;
                i++; // Skip next char
                continue;
            }
            if (in_comment && c == '\n') {
                in_comment = false;
                continue;
            }
            if (!in_comment) {
                if (c == '"') {
                    in_string = true;
                } else if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (c == '=') {
                    have_eq = 1;
                }
            }
        }
        if (depth <= 0 && have_eq) break;
    }
    free(line);
    if (buflen == 0) { *out_lines_read = 0; return NULL; }
    *out_lines_read = lines;
    return buf;
}

//
// Script parsing and execution with enhanced escape safety
//
static IR* parse_script_file_with_escapes(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        perror("fopen script");
        return NULL;
    }
    
    IR* ir = arena_alloc_unlimited(sizeof(IR));  // Use arena
    ir_init(ir);
    int line_num = 1;
    
    while (1) {
        int consumed = 0;
        char *block = read_block_with_comments_and_escapes(f, &consumed);
        if (!block) break;
        
        if (parse_line_strict_with_escapes(block, ir, line_num) == -1) {
            fprintf(stderr, "Parse error in %s at line %d: %s\n", path, line_num, block);
            fclose(f);
            return NULL;  // Arena cleanup handles memory
        }
        line_num += consumed;
    }
    fclose(f);
    
    if (ir->count == 0) {
        fprintf(stderr, "Warning: no valid statements in %s\n", path);
        return NULL;
    }
    return ir;
}

static void run_script_with_escapes(const char* path) {
    IR* ir = parse_script_file_with_escapes(path);
    if (!ir) {
        fprintf(stderr, "Error: failed to parse script %s\n", path);
        return;
    }
    executor_enhanced(ir->stmts, ir->count, env_array);
    // No manual cleanup needed - arena handles everything
}

//
// main - Enhanced with escape support
//
int preload_all = 0;
char *preload_list = NULL;

int main(int argc, char **argv) {
    atexit(cleanup_all);
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.optivar> [--fixed-vars=N] [--table-size=N] [--preload|--preload=list:bin1,bin2,...] [--non-strict]\n", argv[0]);
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
        } else if (strcmp(argv[i], "--non-strict") == 0) {
            strict_mode = 0;
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
        char *list_copy = arena_alloc_unlimited(strlen(preload_list) + 1);  // Safe allocation
        strcpy(list_copy, preload_list);
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
    }
    
    run_script_with_escapes(script_path);
    return 0;
}

/*
EXAMPLE USAGE WITH ESCAPE SEQUENCES:

Now you can write OPTIVAR scripts with escaped strings like:

-- Basic string with escaped quotes
result = str("He said \"Hello World\"")

-- String with escaped equals sign
equation = str("x \= y + 2")  

-- String with escaped parentheses
brackets = str("This has \( and \) inside")

-- String with escaped comma
list = str("item1\, item2\, item3")

-- String with escaped comment
comment_str = str("This contains \-- not a comment")

-- Complex example with multiple escapes
complex = format(msg = str("Error\: value \= \"invalid\", check \(line 5\)"), 
                code = num(404))

-- All escape sequences supported:
--   \" -> "
--   \\ -> \
--   \= -> =
--   \( -> (
--   \) -> )
--   \, -> ,
--   \-- -> --
--   \n -> newline
--   \t -> tab
--   \r -> carriage return
*/
