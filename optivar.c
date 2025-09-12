// optivar.c -- Enhanced superoptimized, memory-safe, minimal, scalable IR executor with strict syntax 
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
#include <sys/inotify.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

//
// Tunables
//
#define DEFAULT_FIXED_VARS 4096
#define VAR_CHUNK_SIZE 8192
#define MAX_NAME_LEN 128
#define CACHE_LINE 64
#define MIN_BIN_SIZE 16
#define BIN_MAGIC 0xDEADBEEF
#define MAX_ERROR_LEN 512

//
// Enhanced Error Reporting System
//
typedef enum {
    ERR_NONE = 0,
    ERR_PARSE_SYNTAX = 1000,
    ERR_PARSE_MISSING_ASSIGN = 1001,
    ERR_PARSE_INVALID_VAR = 1002,
    ERR_PARSE_INVALID_FUNC = 1003,
    ERR_PARSE_UNMATCHED_PAREN = 1004,
    ERR_PARSE_INVALID_ESCAPE = 1005,
    ERR_PARSE_EMPTY_ARG = 1006,
    ERR_EXEC_FUNC_NOT_FOUND = 2000,
    ERR_EXEC_TYPE_MISMATCH = 2001,
    ERR_MEM_ALLOC_FAILED = 3000,
    ERR_FILE_NOT_FOUND = 4000,
    ERR_FILE_READ_ERROR = 4001
} ErrorCode;

typedef struct ErrorInfo {
    ErrorCode code;
    int line;
    int column;
    char message[MAX_ERROR_LEN];
    char context[MAX_ERROR_LEN];
} ErrorInfo;

static ErrorInfo last_error = {0};

static void set_error(ErrorCode code, int line, int column, const char* fmt, ...) {
    last_error.code = code;
    last_error.line = line;
    last_error.column = column;
    
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_error.message, MAX_ERROR_LEN - 1, fmt, args);
    va_end(args);
    last_error.message[MAX_ERROR_LEN - 1] = '\0';
}

static void set_error_context(const char* context_str, int context_len) {
    int copy_len = (context_len < MAX_ERROR_LEN - 1) ? context_len : MAX_ERROR_LEN - 1;
    strncpy(last_error.context, context_str, copy_len);
    last_error.context[copy_len] = '\0';
}

//
// Config (modifiable by argv)
//
static int FIXED_VARS = DEFAULT_FIXED_VARS;
static int var_table_size = 4096;
static int strict_mode = 1;
static int dry_run_mode = 0;

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
    int ref_count;
    char pad[CACHE_LINE - sizeof(ValueType) - sizeof(void*) - sizeof(int)];
} Value;

//
// Cache-aligned basic types
//
typedef struct VarSlot {
    Value* value;
    int in_use;
    int last_use;
    char name[MAX_NAME_LEN];
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
    Value** args;
    int dead;
    char func_name[MAX_NAME_LEN];
    int source_line;
    int source_column;
    char pad[CACHE_LINE - 5*sizeof(int) - sizeof(void*) - sizeof(Value**) - MAX_NAME_LEN];
} IRStmt;

// Static assertions for cache alignment
static_assert(sizeof(VarSlot) % CACHE_LINE == 0, "VarSlot not cache-aligned");
static_assert(sizeof(IRStmt) % CACHE_LINE == 0, "IRStmt not cache-aligned");
static_assert(sizeof(Value) % CACHE_LINE == 0, "Value not cache-aligned");

typedef Value* (*BinFunc)(Value** args, int argc, struct BinContext* ctx);

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
#define ARENA_DEFAULT_SIZE (16 * 1024 * 1024)

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
        set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "Failed to allocate arena chunk");
        exit(EXIT_FAILURE);
    }
    chunk->ptr = malloc(chunk_size);
    if (!chunk->ptr) {
        free(chunk);
        set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "Failed to allocate arena memory");
        exit(EXIT_FAILURE);
    }
    chunk->size = chunk_size;
    chunk->used = 0;
    chunk->next = NULL;
    return chunk;
}

void* arena_alloc_unlimited(size_t size) {
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
    memset(ptr, 0, size);
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
// ENHANCED STRING ESCAPE HANDLING SYSTEM
//
static int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char* process_string_escapes_enhanced(const char* input, int input_len, int* output_len, int line, int col) {
    if (!input || input_len <= 0) {
        *output_len = 0;
        return NULL;
    }
    
    char* result = arena_alloc_unlimited(input_len * 4 + 1);
    int result_pos = 0;
    int i = 0;
    
    while (i < input_len) {
        if (input[i] == '\\' && i + 1 < input_len) {
            char next_char = input[i + 1];
            switch (next_char) {
                case '"':
                    result[result_pos++] = '"';
                    i += 2;
                    break;
                case '\\':
                    result[result_pos++] = '\\';
                    i += 2;
                    break;
                case '=':
                    result[result_pos++] = '=';
                    i += 2;
                    break;
                case '(':
                    result[result_pos++] = '(';
                    i += 2;
                    break;
                case ')':
                    result[result_pos++] = ')';
                    i += 2;
                    break;
                case ',':
                    result[result_pos++] = ',';
                    i += 2;
                    break;
                case '-':
                    if (i + 2 < input_len && input[i + 2] == '-') {
                        result[result_pos++] = '-';
                        result[result_pos++] = '-';
                        i += 3;
                    } else {
                        result[result_pos++] = '-';
                        i += 2;
                    }
                    break;
                case 'n':
                    result[result_pos++] = '\n';
                    i += 2;
                    break;
                case 't':
                    result[result_pos++] = '\t';
                    i += 2;
                    break;
                case 'r':
                    result[result_pos++] = '\r';
                    i += 2;
                    break;
                case '0':
                    result[result_pos++] = '\0';
                    i += 2;
                    break;
                case 'x':
                    if (i + 3 < input_len) {
                        int d1 = hex_digit_value(input[i + 2]);
                        int d2 = hex_digit_value(input[i + 3]);
                        if (d1 >= 0 && d2 >= 0) {
                            result[result_pos++] = (char)(d1 * 16 + d2);
                            i += 4;
                        } else {
                            set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, 
                                    "Invalid hexadecimal escape sequence");
                            return NULL;
                        }
                    } else {
                        set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, 
                                "Incomplete hexadecimal escape sequence");
                        return NULL;
                    }
                    break;
                case 'u':
                    if (i + 5 < input_len) {
                        int code = 0;
                        bool valid = true;
                        for (int j = 2; j < 6; j++) {
                            int d = hex_digit_value(input[i + j]);
                            if (d < 0) {
                                valid = false;
                                break;
                            }
                            code = code * 16 + d;
                        }
                        if (valid && code <= 0x7F) {
                            result[result_pos++] = (char)code;
                            i += 6;
                        } else if (valid) {
                            if (code <= 0x7FF) {
                                result[result_pos++] = (char)(0xC0 | (code >> 6));
                                result[result_pos++] = (char)(0x80 | (code & 0x3F));
                            } else {
                                result[result_pos++] = (char)(0xE0 | (code >> 12));
                                result[result_pos++] = (char)(0x80 | ((code >> 6) & 0x3F));
                                result[result_pos++] = (char)(0x80 | (code & 0x3F));
                            }
                            i += 6;
                        } else {
                            set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, 
                                    "Invalid unicode escape sequence");
                            return NULL;
                        }
                    } else {
                        set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, 
                                "Incomplete unicode escape sequence");
                        return NULL;
                    }
                    break;
                default:
                    set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, 
                            "Unknown escape sequence: \\%c", next_char);
                    return NULL;
            }
        } else {
            result[result_pos++] = input[i];
            i++;
        }
    }
    
    result[result_pos] = '\0';
    *output_len = result_pos;
    return result;
}

static bool is_string_literal_enhanced(const char* str, int len, char** processed_content, 
                                     int* content_len, int line, int col) {
    if (len < 2 || str[0] != '"' || str[len-1] != '"') {
        *processed_content = NULL;
        *content_len = 0;
        return false;
    }
    
    const char* content_start = str + 1;
    int raw_content_len = len - 2;
    
    *processed_content = process_string_escapes_enhanced(content_start, raw_content_len, 
                                                       content_len, line, col + 1);
    return *processed_content != NULL;
}

static bool is_numeric_literal_enhanced(const char* str, int len, long* value, int line, int col) {
    if (len <= 0) return false;
    
    int i = 0;
    bool negative = false;
    
    if (str[0] == '-') {
        negative = true;
        i++;
        if (i >= len) {
            set_error(ERR_PARSE_SYNTAX, line, col, "Invalid number: lone minus sign");
            return false;
        }
    }
    
    if (i >= len || !isdigit((unsigned char)str[i])) {
        set_error(ERR_PARSE_SYNTAX, line, col, "Invalid number format");
        return false;
    }
    
    long result = 0;
    for (; i < len; i++) {
        if (!isdigit((unsigned char)str[i])) {
            set_error(ERR_PARSE_SYNTAX, line, col + i, "Invalid character in number");
            return false;
        }
        
        if (result > (LONG_MAX - (str[i] - '0')) / 10) {
            set_error(ERR_PARSE_SYNTAX, line, col, "Number overflow");
            return false;
        }
        
        result = result * 10 + (str[i] - '0');
    }
    
    *value = negative ? -result : result;
    return true;
}

static int find_argument_boundaries_enhanced(const char* args_str, int args_len, 
                                           int** boundaries, int* arg_count, int line, int col) {
    *boundaries = arena_alloc_unlimited(sizeof(int) * (args_len + 2));
    *arg_count = 0;
    
    int pos = 0;
    int paren_depth = 0;
    bool in_string = false;
    bool escaped = false;
    
    while (pos < args_len && isspace((unsigned char)args_str[pos])) pos++;
    
    if (pos >= args_len) return 0;
    
    (*boundaries)[(*arg_count)++] = pos;
    
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
                if (paren_depth < 0) {
                    set_error(ERR_PARSE_UNMATCHED_PAREN, line, col + pos, 
                            "Unmatched closing parenthesis");
                    return -1;
                }
            } else if (c == ',' && paren_depth == 0) {
                (*boundaries)[(*arg_count)++] = pos;
                
                pos++;
                while (pos < args_len && isspace((unsigned char)args_str[pos])) pos++;
                
                if (pos < args_len) {
                    (*boundaries)[(*arg_count)++] = pos;
                }
                continue;
            }
        }
        pos++;
    }
    
    if (in_string) {
        set_error(ERR_PARSE_SYNTAX, line, col, "Unterminated string literal");
        return -1;
    }
    
    if (paren_depth > 0) {
        set_error(ERR_PARSE_UNMATCHED_PAREN, line, col, "Unmatched opening parenthesis");
        return -1;
    }
    
    if (*arg_count % 2 == 1) {
        (*boundaries)[(*arg_count)++] = args_len;
    }
    
    return *arg_count / 2;
}

//
// Enhanced Value management with type safety
//
static Value* value_create(ValueType type) {
    Value* v = arena_alloc_unlimited(sizeof(Value));
    v->type = type;
    v->ref_count = 1;
    return v;
}

static Value* value_create_string_safe(const char* str) {
    Value* v = value_create(TYPE_STRING);
    if (str) {
        size_t len = strlen(str);
        v->str_val = arena_alloc_unlimited(len + 1);
        memcpy(v->str_val, str, len + 1);
    } else {
        v->str_val = arena_alloc_unlimited(1);
        v->str_val[0] = '\0';
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

static Value* value_create_literal_enhanced(const char* literal_str, int literal_len, 
                                          int line, int col) {
    char* processed_content;
    int content_len;
    
    if (is_string_literal_enhanced(literal_str, literal_len, &processed_content, 
                                 &content_len, line, col)) {
        Value* v = value_create(TYPE_STRING);
        if (processed_content) {
            v->str_val = arena_alloc_unlimited(content_len + 1);
            memcpy(v->str_val, processed_content, content_len + 1);
        } else {
            v->str_val = arena_alloc_unlimited(1);
            v->str_val[0] = '\0';
        }
        return v;
    }
    
    long num_value;
    if (is_numeric_literal_enhanced(literal_str, literal_len, &num_value, line, col)) {
        return value_create_number(num_value);
    }
    
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
}

//
// Variable pools and environment
//
typedef struct VarPoolChunk {
    VarSlot* slots;
    int capacity;
    struct VarPoolChunk* next;
} VarPoolChunk;

static VarSlot* fixed_pool = NULL;
static int fixed_top = 0;
static VarPoolChunk* dynamic_pool = NULL;

static VarSlot** env_array = NULL;
static int var_count = 0;
static int env_alloc_size = 0;

typedef struct HashNode {
    VarSlot* slot;
    char name[MAX_NAME_LEN];
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

static inline unsigned int hash_name(const char* s, int table_size) {
    unsigned int h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)(*s++);
        h *= 16777619u;
    }
    return h % (unsigned int)table_size;
}

static void grow_func_table() {
    int new_size = func_table_size * 2;
    FuncEntry* nt = realloc(func_table, sizeof(FuncEntry) * new_size);
    if (!nt) {
        set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "Failed to grow function table");
        exit(EXIT_FAILURE);
    }
    memset(nt + func_table_size, 0, sizeof(FuncEntry) * (new_size - func_table_size));
    func_table = nt;
    func_table_size = new_size;
}

//
// Binary function loading (enhanced with better error handling)
//
static void* load_binfunc(const char* name, int* arg_count_out, size_t* len_out) {
    char path[512];
    snprintf(path, sizeof(path), "./funcs/%s.bin", name);
    struct stat st;
    if (stat(path, &st) != 0) {
        if (!strict_mode) return NULL;
        set_error(ERR_FILE_NOT_FOUND, 0, 0, "Function file not found: %s", path);
        return NULL;
    }
    if (st.st_size < sizeof(BinHeader) + MIN_BIN_SIZE) {
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Function file too small: %s", path);
        return NULL;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot open function file: %s", path);
        return NULL;
    }
    BinHeader hdr;
    if (read(fd, &hdr, sizeof(BinHeader)) != (ssize_t)sizeof(BinHeader)) {
        close(fd);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot read function header: %s", path);
        return NULL;
    }
    if (hdr.magic != BIN_MAGIC) {
        close(fd);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Invalid function file magic: %s", path);
        return NULL;
    }
    size_t code_size = st.st_size - sizeof(BinHeader);
    void* mapped = mmap(NULL, code_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, sizeof(BinHeader));
    if (mapped == MAP_FAILED) {
        close(fd);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot map function: %s", path);
        return NULL;
    }
    uint32_t crc = crc32(0, (unsigned char*)mapped, code_size);
    if (crc != hdr.code_crc) {
        munmap(mapped, code_size);
        close(fd);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Function CRC mismatch: %s", path);
        return NULL;
    }
    close(fd);
    *arg_count_out = hdr.arg_count;
    *len_out = code_size;
    return mapped;
}

static void preload_binfuncs(const char* dirpath) {
    if (!func_table) {
        func_table = calloc(func_table_size, sizeof(FuncEntry));
        if (!func_table) {
            set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "Cannot allocate function table");
            exit(EXIT_FAILURE);
        }
    }
    DIR* d = opendir(dirpath);
    if (!d) {
        fprintf(stderr, "Warning: cannot open %s\n", dirpath);
        return;
    }
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
// Safe IR helpers
//
static void ir_init(IR* ir) { 
    ir->stmts = NULL; 
    ir->count = ir->capacity = 0; 
}

static IRStmt* ir_alloc_stmt(IR* ir) {
    if (ir->count >= ir->capacity) {
        int newc = ir->capacity ? ir->capacity * 2 : 16;
        IRStmt* tmp = arena_alloc_unlimited(sizeof(IRStmt) * newc);
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
        IRStmt* tmp = arena_alloc_unlimited(sizeof(IRStmt) * newc);
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
    HashNode** nt = arena_alloc_unlimited(sizeof(HashNode*) * new_size);
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
    var_table = nt;
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
    strncpy(s->name, name, MAX_NAME_LEN - 1);
    s->name[MAX_NAME_LEN - 1] = '\0';
    
    HashNode* hn = arena_alloc_unlimited(sizeof(HashNode));
    hn->slot = s;
    strncpy(hn->name, name, MAX_NAME_LEN - 1);
    hn->name[MAX_NAME_LEN - 1] = '\0';
    hn->next = var_table[h];
    var_table[h] = hn;
    
    if (var_count >= env_alloc_size) {
        int ns = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
        VarSlot** ne = arena_alloc_unlimited(sizeof(VarSlot*) * ns);
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
// Initialize environment
//
static void init_env(int total_vars) {
    if (total_vars <= 0) total_vars = FIXED_VARS * 2;
    if (total_vars > (1 << 20)) {
        set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "FIXED_VARS too large");
        exit(EXIT_FAILURE);
    }
    env_alloc_size = total_vars;
    env_array = arena_alloc_unlimited(sizeof(VarSlot*) * env_alloc_size);
    
    fixed_pool = arena_alloc_unlimited(sizeof(VarSlot) * FIXED_VARS);
    memset(fixed_pool, 0, sizeof(VarSlot) * FIXED_VARS);
}

//
// Enhanced parsing helpers with escape support and line/column tracking
//
static bool is_valid_function_call_enhanced(const char* str, int len, int line, int col) {
    if (len <= 2) {
        set_error(ERR_PARSE_INVALID_FUNC, line, col, "Function call too short");
        return false;
    }
    
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
    
    if (!open_paren || open_paren == str) {
        set_error(ERR_PARSE_INVALID_FUNC, line, col, "Missing or invalid function name");
        return false;
    }
    
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
    
    if (!found_close) {
        set_error(ERR_PARSE_UNMATCHED_PAREN, line, col, "Missing closing parenthesis");
        return false;
    }
    
    for (const char* p = str; p < open_paren; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') {
            set_error(ERR_PARSE_INVALID_FUNC, line, col + (p - str), "Invalid character in function name");
            return false;
        }
    }
    
    return true;
}

static bool is_bare_variable_enhanced(const char* str, int len, int line, int col) {
    if (len <= 0) return false;
    
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
            } else if (c == '(' || c == ')') {
                return false;
            } else if (!isalnum((unsigned char)c) && c != '_') {
                return false;
            }
        }
    }
    return true;
}

static bool is_bare_literal_enhanced(const char* str, int len, int line, int col) {
    if (len <= 0) return false;
    
    char* processed_content;
    int content_len;
    if (is_string_literal_enhanced(str, len, &processed_content, &content_len, line, col)) {
        return true;
    }
    
    long dummy;
    return is_numeric_literal_enhanced(str, len, &dummy, line, col);
}

static bool is_comment_line_enhanced(const char* str) {
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
                continue;
            } else if (c == '-' && *(p+1) == '-') {
                return true;
            } else {
                return false;
            }
        }
    }
    return false;
}

static int skip_comments_and_whitespace_enhanced(const char* str, int len, int* pos, int line) {
    while (*pos < len) {
        char c = str[*pos];
        if (isspace((unsigned char)c)) {
            (*pos)++;
            continue;
        }
        
        if (*pos < len - 1 && c == '-' && str[*pos + 1] == '-') {
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
                while (*pos < len && str[*pos] != '\n') (*pos)++;
                if (*pos < len) (*pos)++;
                continue;
            }
        }
        break;
    }
    return *pos < len;
}

static int find_matching_delim_enhanced(const char* str, int start, char open, char close, int line, int col) {
    int delim_count = 1;
    int pos = start + 1;
    bool in_string = false;
    bool escaped = false;
    int str_len = strlen(str);
    
    while (pos < str_len && delim_count > 0) {
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
            if (!skip_comments_and_whitespace_enhanced(str, str_len, &pos, line)) break;
            if (pos >= str_len) break;
            
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
    
    if (delim_count != 0) {
        set_error(ERR_PARSE_UNMATCHED_PAREN, line, col, "Unmatched delimiter");
        return -1;
    }
    
    return pos - 1;
}

//
// Enhanced argument parsing with strict validation
//
static int parse_strict_arguments_enhanced(const char* args_start, const char* args_end, IRStmt* stmt, int line, int col) {
    int args_len = args_end - args_start + 1;
    
    int* boundaries;
    int boundary_count;
    int arg_count = find_argument_boundaries_enhanced(args_start, args_len, &boundaries, &boundary_count, line, col);
    
    if (arg_count < 0) return -1;
    
    stmt->argc = arg_count;
    if (arg_count > 0) {
        stmt->args = arena_alloc_unlimited(sizeof(Value*) * arg_count);
    } else {
        stmt->args = NULL;
        return 0;
    }

    for (int i = 0; i < arg_count; i++) {
        int start_idx = boundaries[i * 2];
        int end_idx = boundaries[i * 2 + 1] - 1;
        
        if (start_idx > end_idx) {
            set_error(ERR_PARSE_EMPTY_ARG, line, col, "Empty argument not allowed in strict mode");
            return -1;
        }
        
        const char* arg_start = args_start + start_idx;
        int arg_len = end_idx - start_idx + 1;
        
        while (arg_len > 0 && isspace((unsigned char)*arg_start)) {
            arg_start++;
            arg_len--;
        }
        while (arg_len > 0 && isspace((unsigned char)arg_start[arg_len-1])) {
            arg_len--;
        }
        
        if (arg_len <= 0) {
            set_error(ERR_PARSE_EMPTY_ARG, line, col, "Empty argument not allowed in strict mode");
            return -1;
        }

        // STRICT RULE: Arguments must follow "var = func(...)" pattern
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
            set_error_context(arg_start, arg_len);
            set_error(ERR_PARSE_MISSING_ASSIGN, line, col, "Argument must follow 'var = func(...)' pattern");
            return -1;
        }

        // Parse assignment within argument
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
            set_error(ERR_PARSE_INVALID_VAR, line, col, "Missing variable name in argument assignment");
            return -1;
        }
        
        if (arg_func_len <= 0) {
            set_error(ERR_PARSE_INVALID_FUNC, line, col, "Missing function call in argument assignment");
            return -1;
        }
        
        // Validate RHS is function call
        if (!is_valid_function_call_enhanced(arg_func_start, arg_func_len, line, col + (arg_func_start - args_start))) {
            return -1;
        }
        
        // Parse nested assignment
        IR nested_ir;
        ir_init(&nested_ir);
        
        char* full_assign = arena_alloc_unlimited(arg_len + 1);
        memcpy(full_assign, arg_start, arg_len);
        full_assign[arg_len] = '\0';
        
        if (parse_expression_strict_enhanced(full_assign, arg_len, &nested_ir, line, col + (arg_start - args_start)) == 0 && nested_ir.count > 0) {
            IRStmt* nested_stmt = arena_alloc_unlimited(sizeof(IRStmt));
            *nested_stmt = nested_ir.stmts[0];
            stmt->args[i] = value_create_stmt(nested_stmt);
        } else {
            return -1;
        }
    }
    return 0;
}

//
// Enhanced block parsing
//
static int parse_inline_block_strict_enhanced(const char* block_start, const char* block_end, StatementBlock* block, int line, int col) {
    block_init(block);
    int block_len = block_end - block_start + 1;

    int* boundaries;
    int boundary_count;
    int arg_count = find_argument_boundaries_enhanced(block_start, block_len, &boundaries, &boundary_count, line, col);
    
    if (arg_count < 0) return -1;
    
    for (int i = 0; i < arg_count; i++) {
        int start_idx = boundaries[i * 2];
        int end_idx = boundaries[i * 2 + 1] - 1;
        
        if (start_idx <= end_idx) {
            const char* stmt_start = block_start + start_idx;
            int stmt_len = end_idx - start_idx + 1;
            
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
                if (parse_expression_strict_enhanced(stmt_start, stmt_len, &nested_ir, line, col + (stmt_start - block_start)) == 0 && nested_ir.count > 0) {
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

// Forward declaration
static int parse_expression_strict_enhanced(const char* expr, int expr_len, IR* ir, int line, int col);

//
// Enhanced expression parsing
//
static int parse_expression_strict_enhanced(const char* expr, int expr_len, IR* ir, int line, int col) {
    int pos = 0;
    if (!skip_comments_and_whitespace_enhanced(expr, expr_len, &pos, line)) {
        set_error(ERR_PARSE_SYNTAX, line, col, "Empty expression after removing comments");
        return -1;
    }
    
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
        set_error(ERR_PARSE_MISSING_ASSIGN, line, col, "Expression must contain assignment operator '='");
        return -1;
    }

    // Parse LHS (variable name)
    const char* lhs_start = expr + pos;
    const char* lhs_end = eq - 1;
    while (lhs_start < lhs_end && isspace((unsigned char)*lhs_start)) lhs_start++;
    while (lhs_end > lhs_start && isspace((unsigned char)*lhs_end)) lhs_end--;
    
    if (lhs_start >= lhs_end) {
        set_error(ERR_PARSE_INVALID_VAR, line, col, "Missing variable name on left side of assignment");
        return -1;
    }
    
    int lhs_len = lhs_end - lhs_start + 1;
    if (lhs_len >= MAX_NAME_LEN) {
        set_error(ERR_PARSE_INVALID_VAR, line, col, "Variable name too long (max %d characters)", MAX_NAME_LEN - 1);
        return -1;
    }
    
    char lhs[MAX_NAME_LEN];
    strncpy(lhs, lhs_start, lhs_len);
    lhs[lhs_len] = '\0';

    // Validate LHS is valid variable name
    if (!is_bare_variable_enhanced(lhs, lhs_len, line, col + (lhs_start - expr))) {
        set_error(ERR_PARSE_INVALID_VAR, line, col + (lhs_start - expr), "Left side must be a simple variable name");
        return -1;
    }

    // Parse RHS
    const char* rhs_start = eq + 1;
    pos = rhs_start - expr;
    if (!skip_comments_and_whitespace_enhanced(expr, expr_len, &pos, line)) {
        set_error(ERR_PARSE_INVALID_FUNC, line, col, "Missing function call on right side of assignment");
        return -1;
    }
    rhs_start = expr + pos;
    
    const char* rhs_end = expr + expr_len - 1;
    while (rhs_end > rhs_start && isspace((unsigned char)*rhs_end)) rhs_end--;
    
    if (rhs_start > rhs_end) {
        set_error(ERR_PARSE_INVALID_FUNC, line, col, "Missing function call on right side of assignment");
        return -1;
    }
    
    int rhs_len = rhs_end - rhs_start + 1;
    int rhs_col = col + (rhs_start - expr);
    
    // STRICT VALIDATION
    if (is_bare_variable_enhanced(rhs_start, rhs_len, line, rhs_col)) {
        set_error(ERR_PARSE_SYNTAX, line, rhs_col, "Variable-to-variable assignment not allowed: %s = %.*s", lhs, rhs_len, rhs_start);
        return -1;
    }
    
    if (is_bare_literal_enhanced(rhs_start, rhs_len, line, rhs_col)) {
        set_error(ERR_PARSE_SYNTAX, line, rhs_col, "Bare literals not allowed, must wrap in function: %s = %.*s should be %s = equal(%.*s)", 
                lhs, rhs_len, rhs_start, lhs, rhs_len, rhs_start);
        return -1;
    }
    
    if (!is_valid_function_call_enhanced(rhs_start, rhs_len, line, rhs_col)) {
        return -1;
    }

    // Extract function name
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
        set_error(ERR_PARSE_INVALID_FUNC, line, rhs_col, "Invalid function call syntax");
        return -1;
    }
    
    const char* fname_end = open_delim - 1;
    while (fname_end > rhs_start && isspace((unsigned char)*fname_end)) fname_end--;
    int fname_len = (int)(fname_end - rhs_start + 1);
    
    if (fname_len <= 0 || fname_len >= MAX_NAME_LEN) {
        set_error(ERR_PARSE_INVALID_FUNC, line, rhs_col, "Invalid function name length");
        return -1;
    }
    
    char fname[MAX_NAME_LEN];
    memcpy(fname, rhs_start, fname_len);
    fname[fname_len] = '\0';

    // Find matching parenthesis
    int close_pos = find_matching_delim_enhanced(rhs_start, (int)(open_delim - rhs_start), '(', ')', line, rhs_col);
    if (close_pos < 0) {
        return -1;
    }
    
    const char* content_start = open_delim + 1;
    const char* content_end = rhs_start + close_pos - 1;
    
    pos = content_start - rhs_start;
    if (skip_comments_and_whitespace_enhanced(rhs_start, close_pos, &pos, line)) {
        content_start = rhs_start + pos;
    }
    
    while (content_end > content_start && isspace((unsigned char)*content_end)) content_end--;

    // Create statement
    IRStmt* stmt = ir_alloc_stmt(ir);
    stmt->lhs_index = var_index(lhs);
    stmt->source_line = line;
    stmt->source_column = col;
    strncpy(stmt->func_name, fname, MAX_NAME_LEN - 1);
    stmt->func_name[MAX_NAME_LEN - 1] = '\0';
    
    // Check for block argument
    if (content_start <= content_end) {
        int* boundaries;
        int boundary_count;
        int arg_count = find_argument_boundaries_enhanced(content_start, content_end - content_start + 1, &boundaries, &boundary_count, line, col + (content_start - expr));
        
        if (arg_count < 0) return -1;
        
        // Check if single argument is a block
        if (arg_count == 1) {
            int start_idx = boundaries[0];
            int end_idx = boundaries[1] - 1;
            if (start_idx <= end_idx) {
                const char* arg_start = content_start + start_idx;
                int arg_len = end_idx - start_idx + 1;
                
                bool is_block = false;
                bool in_string_block = false;
                bool escaped_block = false;
                for (int i = 0; i < arg_len; i++) {
                    char c = arg_start[i];
                    if (in_string_block) {
                        if (escaped_block) escaped_block = false;
                        else if (c == '\\') escaped_block = true;
                        else if (c == '"') in_string_block = false;
                    } else {
                        if (c == '"') in_string_block = true;
                        else if (c == '=') { is_block = true; break; }
                    }
                }
                
                if (is_block) {
                    StatementBlock* block = arena_alloc_unlimited(sizeof(StatementBlock));
                    block_init(block);
                    if (parse_inline_block_strict_enhanced(arg_start, arg_start + arg_len - 1, block, line, col + (arg_start - expr)) != 0) {
                        return -1;
                    }
                    stmt->argc = 1;
                    stmt->args = arena_alloc_unlimited(sizeof(Value*));
                    stmt->args[0] = value_create_block(block);
                    return 0;
                }
            }
        }
        
        // Standard argument parsing
        if (parse_strict_arguments_enhanced(content_start, content_end, stmt, line, col + (content_start - expr)) != 0) {
            return -1;
        }
    } else {
        stmt->argc = 0;
        stmt->args = NULL;
    }
    
    return 0;
}

//
// Enhanced line parsing
//
static int parse_line_strict_enhanced(const char* line, IR* ir, int line_num) {
    int len = strlen(line);
    while (len > 0 && isspace((unsigned char)line[len-1])) len--;
    if (len <= 0) return 0;
    if (is_comment_line_enhanced(line)) return 0;

    if (parse_expression_strict_enhanced(line, len, ir, line_num, 1) != 0) {
        set_error_context(line, len);
        return -1;
    }
    return 0;
}

//
// Enhanced executor - removed flawed "HPC mode" logic
//
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
                set_error(ERR_EXEC_FUNC_NOT_FOUND, stmt->source_line, stmt->source_column, 
                         "Function '%s' not found", stmt->func_name);
                continue;
            }
            continue;
        }
        
        // Prepare arguments with type safety
        Value** args = stmt->args;
        for (int j = 0; j < stmt->argc; j++) {
            if (!args[j]) continue;
            
            if (args[j]->type == TYPE_STMT) {
                IRStmt* nested = args[j]->stmt_val;
                StatementBlock temp_block = {
                    .stmts = nested,
                    .count = 1,
                    .capacity = 1
                };
                Value* result = execute_statement_block(ctx, &temp_block);
                value_release(args[j]);
                args[j] = result;
                if (args[j]) value_retain(args[j]);
            } else if (args[j]->type == TYPE_BLOCK) {
                Value* result = execute_statement_block(ctx, args[j]->block_val);
                value_release(args[j]);
                args[j] = result;
                if (args[j]) value_retain(args[j]);
            }
        }
        
        VarSlot* lhs = (stmt->lhs_index >= 0 && stmt->lhs_index < var_count) ? ctx->env[stmt->lhs_index] : NULL;
        if (!lhs) continue;
        
        BinFunc fn = (BinFunc)stmt->func_ptr;
        Value* result = fn(args, stmt->argc, ctx);
        
        if (result) {
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
                set_error(ERR_EXEC_FUNC_NOT_FOUND, stmt->source_line, stmt->source_column, 
                         "Function '%s' not found", stmt->func_name);
                if (dry_run_mode) continue;
                exit(EXIT_FAILURE);
            }
            continue;
        }
        
        if (dry_run_mode) continue; // Skip execution in dry-run
        
        // Prepare arguments with type safety
        Value** args = stmt->args;
        for (int j = 0; j < stmt->argc; j++) {
            if (!args[j]) continue;
            
            if (args[j]->type == TYPE_STMT) {
                IRStmt* nested = args[j]->stmt_val;
                StatementBlock temp_block = {
                    .stmts = nested,
                    .count = 1,
                    .capacity = 1
                };
                Value* result = execute_statement_block(&global_bin_context, &temp_block);
                value_release(args[j]);
                args[j] = result;
                if (args[j]) value_retain(args[j]);
            } else if (args[j]->type == TYPE_BLOCK) {
                Value* result = execute_statement_block(&global_bin_context, args[j]->block_val);
                value_release(args[j]);
                args[j] = result;
                if (args[j]) value_retain(args[j]);
            }
        }
        
        VarSlot* lhs = (stmt->lhs_index >= 0 && stmt->lhs_index < var_count) ? env[stmt->lhs_index] : NULL;
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
    if (env_array) {
        for (int i = 0; i < var_count; ++i) {
            if (env_array[i] && env_array[i]->value) {
                value_release(env_array[i]->value);
            }
        }
    }
    
    if (func_table) {
        for (int i = 0; i < func_count; ++i) {
            if (func_table[i].ptr && func_table[i].len > 0) {
                munmap(func_table[i].ptr, func_table[i].len);
            }
        }
        free(func_table);
        func_table = NULL;
    }
    
    arena_free_all();
    
    env_array = NULL;
    var_table = NULL;
    fixed_pool = NULL;
    dynamic_pool = NULL;
    var_count = 0;
    fixed_top = 0;
}

static char* read_block_enhanced(FILE* f, int *out_lines_read, int starting_line) {
    char *line = NULL;
    size_t lcap = 0;
    ssize_t r;
    size_t bufcap = 4096;
    char *buf = arena_alloc_unlimited(bufcap);
    size_t buflen = 0;
    int depth = 0;
    int lines = 0;
    int have_eq = 0;
    
    while ((r = getline(&line, &lcap, f)) != -1) {
        lines++;
        
        if (is_comment_line_enhanced(line)) {
            continue;
        }
        
        if (buflen + (size_t)r + 1 > bufcap) {
            while (buflen + (size_t)r + 1 > bufcap) bufcap *= 2;
            char *nb = arena_alloc_unlimited(bufcap);
            memcpy(nb, buf, buflen);
            buf = nb;
        }
        memcpy(buf + buflen, line, (size_t)r);
        buflen += (size_t)r;
        buf[buflen] = '\0';
        
        // Count parentheses with escape awareness
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
                i++;
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
// Enhanced script parsing (removed flawed HPC mode detection)
//
static IR* parse_script_file_enhanced(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        set_error(ERR_FILE_NOT_FOUND, 0, 0, "Cannot open script file: %s", path);
        return NULL;
    }
    
    IR* ir = arena_alloc_unlimited(sizeof(IR));
    ir_init(ir);
    int line_num = 1;
    
    while (1) {
        int consumed = 0;
        char *block = read_block_enhanced(f, &consumed, line_num);
        if (!block) break;
        
        if (parse_line_strict_enhanced(block, ir, line_num) == -1) {
            fclose(f);
            return NULL;
        }
        line_num += consumed;
    }
    fclose(f);
    
    if (ir->count == 0) {
        set_error(ERR_PARSE_SYNTAX, 0, 0, "No valid statements found in %s", path);
        return NULL;
    }
    return ir;
}

static void run_script_enhanced(const char* path) {
    IR* ir = parse_script_file_enhanced(path);
    if (!ir) {
        fprintf(stderr, "Parse error: %s", last_error.message);
        if (last_error.line > 0) {
            fprintf(stderr, " (line %d", last_error.line);
            if (last_error.column > 0) {
                fprintf(stderr, ", col %d", last_error.column);
            }
            fprintf(stderr, ")");
        }
        if (last_error.context[0]) {
            fprintf(stderr, "\nContext: %s", last_error.context);
        }
        fprintf(stderr, "\n");
        return;
    }
    
    // Execute statements - all functions can have block arguments
    executor_enhanced(ir->stmts, ir->count, env_array);
    
    // No special "HPC mode" - just regular execution with optional monitoring
    if (dry_run_mode) return;
    
    // Cross-platform file monitoring
    FileWatcher* watcher = create_file_watcher(path);
    if (!watcher) {
        // Fallback to simple polling
        time_t last_mod = get_file_mtime(path);
        while (1) {
            time_t current_mod = get_file_mtime(path);
            if (current_mod > last_mod) {
                last_mod = current_mod;
                
                // Clear environment
                for (int i = 0; i < var_count; i++) {
                    if (env_array[i] && env_array[i]->value) {
                        value_release(env_array[i]->value);
                        env_array[i]->value = NULL;
                    }
                }
                
                // Re-parse and execute
                IR* new_ir = parse_script_file_enhanced(path);
                if (new_ir) {
                    executor_enhanced(new_ir->stmts, new_ir->count, env_array);
                }
            }
            sleep(1);
        }
    } else {
        // Use platform-specific file monitoring
        while (1) {
            if (check_file_changed(watcher)) {
                // Clear environment
                for (int i = 0; i < var_count; i++) {
                    if (env_array[i] && env_array[i]->value) {
                        value_release(env_array[i]->value);
                        env_array[i]->value = NULL;
                    }
                }
                
                // Re-parse and execute
                IR* new_ir = parse_script_file_enhanced(path);
                if (new_ir) {
                    executor_enhanced(new_ir->stmts, new_ir->count, env_array);
                }
            }
            sleep(1);
        }
        
        destroy_file_watcher(watcher);
    }
}
            fprintf(stderr, ")");
        }
        if (last_error.context[0]) {
            fprintf(stderr, "\nContext: %s", last_error.context);
        }
        fprintf(stderr, "\n");
        return;
    }
    
    // Execute statements - all functions can have block arguments
    executor_enhanced(ir->stmts, ir->count, env_array);
    
    // No special "HPC mode" - just regular execution with optional monitoring
    if (dry_run_mode) return;
    
    // Dynamic mode: Monitor file changes if not in dry-run
    int fd = inotify_init();
    if (fd < 0) {
        // Fallback to polling
        time_t last_mod = 0;
        struct stat st;
        while (1) {
            if (stat(path, &st) == 0 && st.st_mtime > last_mod) {
                last_mod = st.st_mtime;
                // Clear environment
                for (int i = 0; i < var_count; i++) {
                    if (env_array[i] && env_array[i]->value) {
                        value_release(env_array[i]->value);
                        env_array[i]->value = NULL;
                    }
                }
                // Re-parse and execute
                IR* new_ir = parse_script_file_enhanced(path);
                if (new_ir) {
                    executor_enhanced(new_ir->stmts, new_ir->count, env_array);
                }
            }
            sleep(1);
        }
    } else {
        int wd = inotify_add_watch(fd, path, IN_MODIFY | IN_CREATE | IN_DELETE);
        if (wd < 0) {
            perror("inotify_add_watch");
            close(fd);
            return;
        }
        
        while (1) {
            char buffer[4096];
            ssize_t len = read(fd, buffer, sizeof(buffer));
            if (len <= 0) continue;
            
            // Clear environment
            for (int i = 0; i < var_count; i++) {
                if (env_array[i] && env_array[i]->value) {
                    value_release(env_array[i]->value);
                    env_array[i]->value = NULL;
                }
            }
            // Re-parse and execute
            IR* new_ir = parse_script_file_enhanced(path);
            if (new_ir) {
                executor_enhanced(new_ir->stmts, new_ir->count, env_array);
            }
        }
        
        inotify_rm_watch(fd, wd);
        close(fd);
    }
}

//
// Testing and Debugging Support
//
typedef struct TestCase {
    const char* name;
    const char* input;
    const char* expected_output;
    bool should_fail;
    ErrorCode expected_error;
} TestCase;

static TestCase escape_tests[] = {
    {"Basic escapes", "\"Hello\\nWorld\"", "Hello\nWorld", false, ERR_NONE},
    {"Hex escapes", "\"\\x48\\x65\\x6C\\x6C\\x6F\"", "Hello", false, ERR_NONE},
    {"Unicode escapes", "\"\\u0048\\u0065\\u006C\\u006C\\u006F\"", "Hello", false, ERR_NONE},
    {"Invalid hex", "\"\\xGG\"", NULL, true, ERR_PARSE_INVALID_ESCAPE},
    {"Invalid unicode", "\"\\uGGGG\"", NULL, true, ERR_PARSE_INVALID_ESCAPE},
    {"Null character", "\"Test\\x00End\"", "Test\0End", false, ERR_NONE},
    {"Mixed escapes", "\"Line1\\nTab\\tEnd\"", "Line1\nTab\tEnd", false, ERR_NONE},
    {NULL, NULL, NULL, false, ERR_NONE}
};

static void run_escape_tests() {
    printf("Running escape sequence tests...\n");
    int passed = 0, total = 0;
    
    for (TestCase* test = escape_tests; test->name; test++) {
        total++;
        printf("  %s: ", test->name);
        
        char* processed;
        int len;
        last_error.code = ERR_NONE; // Reset
        bool result = is_string_literal_enhanced(test->input, strlen(test->input), 
                                               &processed, &len, 1, 1);
        
        if (test->should_fail) {
            if (!result && last_error.code == test->expected_error) {
                printf("PASS (correctly failed)\n");
                passed++;
            } else {
                printf("FAIL (should have failed with error %d, got %d)\n", 
                       test->expected_error, last_error.code);
            }
        } else {
            if (result && processed) {
                bool match = (len == strlen(test->expected_output)) && 
                           (memcmp(processed, test->expected_output, len) == 0);
                if (match) {
                    printf("PASS\n");
                    passed++;
                } else {
                    printf("FAIL (length or content mismatch)\n");
                }
            } else {
                printf("FAIL (processing failed: %s)\n", last_error.message);
            }
        }
    }
    
    printf("Escape tests: %d/%d passed\n\n", passed, total);
}

static void run_strict_mode_tests() {
    printf("Running strict mode validation tests...\n");
    
    const char* valid_cases[] = {
        "x = func()",
        "result = calculate(a = add(1, 2))",
        "output = process(data = load(\"file.txt\"))",
        NULL
    };
    
    const char* invalid_cases[] = {
        "x = y",                    // Variable assignment
        "x = \"literal\"",          // Bare literal  
        "x = 42",                   // Bare number
        "func()",                   // No assignment
        "= func()",                 // Missing LHS
        "x =",                      // Missing RHS
        NULL
    };
    
    int passed = 0, total = 0;
    
    // Test valid cases
    for (int i = 0; valid_cases[i]; i++) {
        total++;
        printf("  Valid: %s: ", valid_cases[i]);
        
        IR test_ir;
        ir_init(&test_ir);
        last_error.code = ERR_NONE;
        
        int result = parse_expression_strict_enhanced(valid_cases[i], strlen(valid_cases[i]), 
                                                    &test_ir, 1, 1);
        if (result == 0 && test_ir.count > 0) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (%s)\n", last_error.message);
        }
    }
    
    // Test invalid cases
    for (int i = 0; invalid_cases[i]; i++) {
        total++;
        printf("  Invalid: %s: ", invalid_cases[i]);
        
        IR test_ir;
        ir_init(&test_ir);
        last_error.code = ERR_NONE;
        
        int result = parse_expression_strict_enhanced(invalid_cases[i], strlen(invalid_cases[i]), 
                                                    &test_ir, 1, 1);
        if (result != 0) {
            printf("PASS (correctly rejected)\n");
            passed++;
        } else {
            printf("FAIL (should have been rejected)\n");
        }
    }
    
    printf("Strict mode tests: %d/%d passed\n\n", passed, total);
}

static void run_dry_run_tests(const char* script_path) {
    printf("Running dry-run validation for: %s\n", script_path);
    
    IR* ir = parse_script_file_enhanced(script_path);
    if (!ir) {
        printf("Parse failed: %s", last_error.message);
        if (last_error.line > 0) {
            printf(" (line %d", last_error.line);
            if (last_error.column > 0) {
                printf(", col %d", last_error.column);
            }
            printf(")");
        }
        printf("\n");
        return;
    }
    
    printf("Successfully parsed %d statements:\n", ir->count);
    for (int i = 0; i < ir->count; i++) {
        IRStmt* stmt = &ir->stmts[i];
        VarSlot* lhs_slot = (stmt->lhs_index >= 0 && stmt->lhs_index < var_count) ? 
                           env_array[stmt->lhs_index] : NULL;
        printf("  [%d] %s = %s(...) with %d args (line %d, col %d)\n", 
               i, lhs_slot ? lhs_slot->name : "unknown",
               stmt->func_name, stmt->argc, stmt->source_line, stmt->source_column);
        
        // Validate function exists
        size_t len;
        int arg_count;
        void* func_ptr = get_func_ptr(stmt->func_name, &arg_count, &len);
        if (!func_ptr) {
            printf("    WARNING: Function '%s' not found\n", stmt->func_name);
        }
    }
    
    printf("Dry-run validation complete.\n");
}

//
// Enhanced main with comprehensive testing support
//
int preload_all = 0;
char *preload_list = NULL;

int main(int argc, char **argv) {
    atexit(cleanup_all);
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.optivar> [options]\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  --fixed-vars=N       Set fixed variable pool size (default: %d)\n", DEFAULT_FIXED_VARS);
        fprintf(stderr, "  --table-size=N       Set hash table size (default: 4096)\n");
        fprintf(stderr, "  --non-strict         Disable strict OPTIVAR mode\n");
        fprintf(stderr, "  --dry-run            Parse and validate without execution\n");
        fprintf(stderr, "  --test-escapes       Run escape sequence unit tests\n");
        fprintf(stderr, "  --test-strict        Run strict mode validation tests\n");
        fprintf(stderr, "  --test-all           Run all unit tests\n");
        fprintf(stderr, "  --preload            Preload all functions at startup\n");
        fprintf(stderr, "  --preload=list:a,b   Preload specific functions\n");
        return 1;
    }
    
    FIXED_VARS = DEFAULT_FIXED_VARS;
    var_table_size = 4096;
    char *script_path = NULL;
    bool run_escape_tests_flag = false;
    bool run_strict_tests_flag = false;
    bool run_all_tests_flag = false;
    
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
        } else if (strncmp(argv[i], "--func-dir=", 11) == 0) {
            func_directory = argv[i] + 11;
        } else if (strcmp(argv[i], "--preload") == 0) {
            preload_all = 1;
        } else if (strncmp(argv[i], "--preload=list:", 15) == 0) {
            preload_list = argv[i] + 15;
        } else if (strcmp(argv[i], "--non-strict") == 0) {
            strict_mode = 0;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run_mode = 1;
        } else if (strcmp(argv[i], "--test-escapes") == 0) {
            run_escape_tests_flag = true;
        } else if (strcmp(argv[i], "--test-strict") == 0) {
            run_strict_tests_flag = true;
        } else if (strcmp(argv[i], "--test-all") == 0) {
            run_all_tests_flag = true;
        } else if (argv[i][0] != '-') {
            script_path = argv[i];
        }
    }
    
    // Show platform info if requested
    if (show_platform_flag) {
        print_platform_info();
        return 0;
    }
    
    // Run tests if requested
    if (run_all_tests_flag || run_escape_tests_flag) {
        run_escape_tests();
    }
    if (run_all_tests_flag || run_strict_tests_flag) {
        run_strict_mode_tests();
    }
    if (run_all_tests_flag || run_escape_tests_flag || run_strict_tests_flag) {
        if (!script_path) return 0; // Exit after tests if no script provided
    }
    
    if (!script_path) {
        set_error(ERR_FILE_NOT_FOUND, 0, 0, "No script specified");
        fprintf(stderr, "Error: %s\n", last_error.message);
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
        char *list_copy = arena_alloc_unlimited(strlen(preload_list) + 1);
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
    
    if (dry_run_mode) {
        run_dry_run_tests(script_path);
        return 0;
    }
    
    run_script_enhanced(script_path);
    return 0;
}
