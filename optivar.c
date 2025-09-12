//
// optivar.c -- Fully cross-platform, memory-safe, minimalistic, superoptimized, scalable IR executor
// Build:
//   gcc -O3 -o optivar optivar.c  (Linux, macOS, MinGW on Windows)
//   cl /O2 /W3 optivar.c          (MSVC on Windows)
//

#if defined(_MSC_VER)
    #define _CRT_SECURE_NO_WARNINGS
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <io.h>
    #include <direct.h>
    #include <intrin.h> // For _BitScanReverse
#else
    #include <dirent.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <dlfcn.h>
#endif

// ----------------- Platform abstraction -----------------
#if defined(_WIN32) || defined(_WIN64)
    #define sleep_ms(ms) Sleep(ms)
    #define PATH_SEPARATOR '\\'
    #define LOAD_LIB(path) LoadLibraryA(path)
    #define GET_FUNC(lib, name) GetProcAddress(lib, name)
    #define CLOSE_LIB(lib) FreeLibrary(lib)
    #define FILE_MOD_TIME(path, out) { \
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); \
        if (hFile != INVALID_HANDLE_VALUE) { \
            FILETIME ft; \
            if (GetFileTime(hFile, NULL, NULL, &ft)) { \
                ULARGE_INTEGER ull; \
                ull.LowPart = ft.dwLowDateTime; \
                ull.HighPart = ft.dwHighDateTime; \
                *(out) = (time_t)(ull.QuadPart / 10000000ULL - 11644473600ULL); \
            } \
            CloseHandle(hFile); \
        } else *(out) = 0; \
    }
#else
    #define sleep_ms(ms) usleep((ms) * 1000)
    #define PATH_SEPARATOR '/'
    #define LOAD_LIB(path) dlopen(path, RTLD_NOW)
    #define GET_FUNC(lib, name) dlsym(lib, name)
    #define CLOSE_LIB(lib) dlclose(lib)
    #define FILE_MOD_TIME(path, out) { \
        struct stat st; \
        if (stat(path, &st) == 0) *(out) = st.st_mtime; \
        else *(out) = 0; \
    }
#endif

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
static char* func_directory = "funcs"; // Default function directory

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
static int parse_expression_strict_enhanced(const char* expr, int expr_len, struct IR* ir, int line, int col);


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

typedef struct StatementBlock {
    IRStmt* stmts;
    int count;
    int capacity;
} StatementBlock;

typedef struct IR {
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

// Static assertions for cache alignment
#if !defined(_MSC_VER)
static_assert(sizeof(VarSlot) % CACHE_LINE == 0, "VarSlot not cache-aligned");
static_assert(sizeof(IRStmt) % CACHE_LINE == 0, "IRStmt not cache-aligned");
static_assert(sizeof(Value) % CACHE_LINE == 0, "Value not cache-aligned");
#endif

typedef Value* (*BinFunc)(Value** args, int argc, struct BinContext* ctx);

typedef struct BinContext {
    VarSlot** env;
    struct FuncEntry* func_table;
    int func_count;
} BinContext;

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
// CRC32 implementation (added to resolve missing function)
//
uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static uint32_t crc32(uint32_t crc, const unsigned char *buf, size_t len) {
    crc = ~crc;
    while (len--) {
        crc = crc32_tab[(crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
    }
    return ~crc;
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
        // This is not necessarily an error, just not a number.
        // set_error(ERR_PARSE_SYNTAX, line, col, "Invalid number format");
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
#if defined(_WIN32) || defined(_WIN64)
typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
} MappedBin;
#else
typedef void* MappedBin;
#endif

typedef struct FuncEntry {
    char name[MAX_NAME_LEN];
    void* ptr;
    size_t len;
    int arg_count;
    MappedBin mapped_bin_handle;
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
// Binary function loading (cross-platform)
//
static void* load_binfunc(const char* name, int* arg_count_out, size_t* len_out, MappedBin* mapped_bin_out) {
    char path[512];
    snprintf(path, sizeof(path), "%s%c%s.bin", func_directory, PATH_SEPARATOR, name);
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        if (!strict_mode) return NULL;
        set_error(ERR_FILE_NOT_FOUND, 0, 0, "Function file not found: %s", path);
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < sizeof(BinHeader) + MIN_BIN_SIZE) {
        fclose(f);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Function file too small: %s", path);
        return NULL;
    }

    BinHeader hdr;
    if (fread(&hdr, 1, sizeof(BinHeader), f) != sizeof(BinHeader)) {
        fclose(f);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot read function header: %s", path);
        return NULL;
    }

    if (hdr.magic != BIN_MAGIC) {
        fclose(f);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Invalid function file magic: %s", path);
        return NULL;
    }
    
    fclose(f); // Close file, we will re-open for mapping to be safe.

    size_t code_size = file_size - sizeof(BinHeader);
    void* mapped_code = NULL;

#if defined(_WIN32) || defined(_WIN64)
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot open function file for mapping: %s", path);
        return NULL;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
    if (hMap == NULL) {
        CloseHandle(hFile);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot create file mapping: %s", path);
        return NULL;
    }

    mapped_code = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, sizeof(BinHeader), code_size);
    if (mapped_code == NULL) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot map view of file: %s", path);
        return NULL;
    }
    mapped_bin_out->file_handle = hFile;
    mapped_bin_out->map_handle = hMap;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot open function file for mapping: %s", path);
        return NULL;
    }
    mapped_code = mmap(NULL, code_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, sizeof(BinHeader));
    if (mapped_code == MAP_FAILED) {
        close(fd);
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot map function: %s", path);
        return NULL;
    }
    close(fd); // fd no longer needed after mmap
#endif

    uint32_t crc = crc32(0, (unsigned char*)mapped_code, code_size);
    if (crc != hdr.code_crc) {
        // Unmap memory
#if defined(_WIN32) || defined(_WIN64)
        UnmapViewOfFile(mapped_code);
        CloseHandle(mapped_bin_out->map_handle);
        CloseHandle(mapped_bin_out->file_handle);
#else
        munmap(mapped_code, code_size);
#endif
        set_error(ERR_FILE_READ_ERROR, 0, 0, "Function CRC mismatch: %s", path);
        return NULL;
    }
    
    *arg_count_out = hdr.arg_count;
    *len_out = code_size;
    return mapped_code;
}

static void preload_binfuncs(const char* dirpath) {
    if (!func_table) {
        func_table = calloc(func_table_size, sizeof(FuncEntry));
        if (!func_table) {
            set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "Cannot allocate function table");
            exit(EXIT_FAILURE);
        }
    }
#if defined(_WIN32) || defined(_WIN64)
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s\\*.bin", dirpath);
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);

    if (find_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Warning: cannot open function directory %s\n", dirpath);
        return;
    }

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            size_t n = strlen(find_data.cFileName);
            if (n > 4 && strcmp(find_data.cFileName + n - 4, ".bin") == 0) {
                if (func_count >= func_table_size) grow_func_table();
                size_t namelen = n - 4;
                if (namelen >= MAX_NAME_LEN) continue;
                strncpy(func_table[func_count].name, find_data.cFileName, namelen);
                func_table[func_count].name[namelen] = '\0';
                func_table[func_count].ptr = NULL;
                func_table[func_count].len = 0;
                func_table[func_count].arg_count = -1;
                func_count++;
            }
        }
    } while (FindNextFileA(find_handle, &find_data) != 0);

    FindClose(find_handle);
#else
    DIR* d = opendir(dirpath);
    if (!d) {
        fprintf(stderr, "Warning: cannot open %s\n", dirpath);
        return;
    }
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        // Check if regular file
        #ifdef _DIRENT_HAVE_D_TYPE
        if (e->d_type != DT_REG && e->d_type != DT_UNKNOWN) continue;
        #endif
        
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
#endif
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
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count, &func_table[i].len, &func_table[i].mapped_bin_handle);
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
        // Not necessarily an error, just not a function call
        // set_error(ERR_PARSE_INVALID_FUNC, line, col, "Function call too short");
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
        // set_error(ERR_PARSE_INVALID_FUNC, line, col, "Missing or invalid function name");
        return false;
    }
    
    in_string = false;
    escaped = false;
    bool found_close = false;
    
    for (int i = len - 1; i >= 0; i--) {
        char c = str[i];
        
        if (in_string) {
            // simplified check: just look for non-escaped quote
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
        // set_error(ERR_PARSE_UNMATCHED_PAREN, line, col, "Missing closing parenthesis");
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
            } else if (c == '=' || c == ',') {
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

static int find_matching_delim_enhanced(const char* str, int str_len, int start, char open, char close, int line, int col) {
    int delim_count = 1;
    int pos = start + 1;
    bool in_string = false;
    bool escaped = false;
    
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
    int args_len = args_end - args_start;
    
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
        int end_idx = boundaries[i * 2 + 1];
        
        const char* arg_start = args_start + start_idx;
        int arg_len = end_idx - start_idx;
        
        while (arg_len > 0 && isspace((unsigned char)*arg_start)) {
            arg_start++;
            arg_len--;
        }
        while (arg_len > 0 && isspace((unsigned char)arg_start[arg_len-1])) {
            arg_len--;
        }
        
        if (arg_len <= 0) {
             if (strict_mode) {
                set_error(ERR_PARSE_EMPTY_ARG, line, col, "Empty argument not allowed in strict mode");
                return -1;
            }
            stmt->args[i] = value_create_string_safe(""); // Allow empty args in non-strict
            continue;
        }

        // Check for literals first
        char* processed_str;
        int processed_len;
        if (is_string_literal_enhanced(arg_start, arg_len, &processed_str, &processed_len, line, col + (arg_start - args_start))) {
            stmt->args[i] = value_create_string_safe(processed_str);
            continue;
        }
        long num_val;
        if (is_numeric_literal_enhanced(arg_start, arg_len, &num_val, line, col + (arg_start - args_start))) {
            stmt->args[i] = value_create_number(num_val);
            continue;
        }

        // Check for nested assignment (sub-expression)
        IR nested_ir;
        ir_init(&nested_ir);
        if (parse_expression_strict_enhanced(arg_start, arg_len, &nested_ir, line, col + (arg_start - args_start)) == 0 && nested_ir.count > 0) {
            IRStmt* nested_stmt = arena_alloc_unlimited(sizeof(IRStmt));
            *nested_stmt = nested_ir.stmts[0];
            stmt->args[i] = value_create_stmt(nested_stmt);
        } else {
             // Treat as a bareword string if parsing as expression fails
            char* bareword = arena_alloc_unlimited(arg_len + 1);
            strncpy(bareword, arg_start, arg_len);
            bareword[arg_len] = '\0';
            stmt->args[i] = value_create_string_safe(bareword);
        }
    }
    return 0;
}

//
// Enhanced block parsing
//
static int parse_inline_block_strict_enhanced(const char* block_start, const char* block_end, StatementBlock* block, int line, int col) {
    block_init(block);
    int block_len = block_end - block_start;

    int* boundaries;
    int boundary_count;
    int arg_count = find_argument_boundaries_enhanced(block_start, block_len, &boundaries, &boundary_count, line, col);
    
    if (arg_count < 0) return -1;
    
    for (int i = 0; i < arg_count; i++) {
        int start_idx = boundaries[i * 2];
        int end_idx = boundaries[i * 2 + 1];
        
        if (start_idx < end_idx) {
            const char* stmt_start = block_start + start_idx;
            int stmt_len = end_idx - start_idx;
            
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

//
// Enhanced expression parsing
//
static int parse_expression_strict_enhanced(const char* expr, int expr_len, IR* ir, int line, int col) {
    int pos = 0;
    skip_comments_and_whitespace_enhanced(expr, expr_len, &pos, line);
    
    const char* eq = NULL;
    bool in_string = false;
    bool escaped = false;
    int paren_depth = 0;
    
    for (int i = pos; i < expr_len; i++) {
        char c = expr[i];
        if (in_string) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_string = false;
        } else {
            if (c == '"') in_string = true;
            else if (c == '(') paren_depth++;
            else if (c == ')') paren_depth--;
            else if (c == '=' && paren_depth == 0) {
                eq = expr + i;
                break;
            }
        }
    }
    
    if (!eq) {
        if (strict_mode) {
            set_error(ERR_PARSE_MISSING_ASSIGN, line, col, "Expression must contain assignment operator '='");
            return -1;
        }
        return -1; // Cannot parse without assignment
    }

    // Parse LHS (variable name)
    const char* lhs_start = expr + pos;
    const char* lhs_end = eq - 1;
    while (lhs_start <= lhs_end && isspace((unsigned char)*lhs_start)) lhs_start++;
    while (lhs_end >= lhs_start && isspace((unsigned char)*lhs_end)) lhs_end--;
    
    if (lhs_start > lhs_end) {
        set_error(ERR_PARSE_INVALID_VAR, line, col, "Missing variable name on left side of assignment");
        return -1;
    }
    
    int lhs_len = (int)(lhs_end - lhs_start + 1);
    if (lhs_len >= MAX_NAME_LEN) {
        set_error(ERR_PARSE_INVALID_VAR, line, col, "Variable name too long (max %d characters)", MAX_NAME_LEN - 1);
        return -1;
    }
    
    char lhs[MAX_NAME_LEN];
    strncpy(lhs, lhs_start, lhs_len);
    lhs[lhs_len] = '\0';

    if (!is_bare_variable_enhanced(lhs, lhs_len, line, col + (int)(lhs_start - expr))) {
        set_error(ERR_PARSE_INVALID_VAR, line, col + (int)(lhs_start - expr), "Left side must be a simple variable name");
        return -1;
    }

    // Parse RHS
    pos = eq - expr + 1;
    skip_comments_and_whitespace_enhanced(expr, expr_len, &pos, line);
    const char* rhs_start = expr + pos;
    
    const char* rhs_end = expr + expr_len - 1;
    while (rhs_end > rhs_start && isspace((unsigned char)*rhs_end)) rhs_end--;
    
    int rhs_len = (int)(rhs_end - rhs_start + 1);
    int rhs_col = col + (int)(rhs_start - expr);
    
    if (rhs_len <= 0) {
         set_error(ERR_PARSE_INVALID_FUNC, line, rhs_col, "Missing expression on right side of assignment");
         return -1;
    }

    if (strict_mode) {
        if (is_bare_variable_enhanced(rhs_start, rhs_len, line, rhs_col)) {
            set_error(ERR_PARSE_SYNTAX, line, rhs_col, "Variable-to-variable assignment not allowed: %s = %.*s", lhs, rhs_len, rhs_start);
            return -1;
        }
        if (is_bare_literal_enhanced(rhs_start, rhs_len, line, rhs_col)) {
            set_error(ERR_PARSE_SYNTAX, line, rhs_col, "Bare literals not allowed, must wrap in function: %s = %.*s should be %s = equal(%.*s)", 
                    lhs, rhs_len, rhs_start, lhs, rhs_len, rhs_start);
            return -1;
        }
    }
    
    if (!is_valid_function_call_enhanced(rhs_start, rhs_len, line, rhs_col)) {
        if (strict_mode) {
             set_error(ERR_PARSE_INVALID_FUNC, line, rhs_col, "Right side must be a valid function call");
             return -1;
        }
        // In non-strict mode, we can allow assignment of literals etc.
        // Let's create an "equal" function call implicitly.
        char* new_expr = arena_alloc_unlimited(rhs_len + 10);
        sprintf(new_expr, "equal(%.*s)", rhs_len, rhs_start);
        rhs_start = new_expr;
        rhs_len = strlen(new_expr);
    }

    // Extract function name
    const char* open_delim = NULL;
    in_string = false;
    escaped = false;
    
    for (const char* p = rhs_start; p < rhs_start + rhs_len; p++) {
        char c = *p;
        if (in_string) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_string = false;
        } else {
            if (c == '"') in_string = true;
            else if (c == '(') {
                open_delim = p;
                break;
            }
        }
    }
    
    if (!open_delim) {
        set_error(ERR_PARSE_INVALID_FUNC, line, rhs_col, "Invalid function call syntax (missing '()')");
        return -1;
    }
    
    int fname_len = (int)(open_delim - rhs_start);
    if (fname_len <= 0 || fname_len >= MAX_NAME_LEN) {
        set_error(ERR_PARSE_INVALID_FUNC, line, rhs_col, "Invalid function name length");
        return -1;
    }
    
    char fname[MAX_NAME_LEN];
    memcpy(fname, rhs_start, fname_len);
    fname[fname_len] = '\0';

    int close_pos = find_matching_delim_enhanced(rhs_start, rhs_len, (int)(open_delim - rhs_start), '(', ')', line, rhs_col);
    if (close_pos < 0) {
        return -1;
    }
    
    const char* content_start = open_delim + 1;
    const char* content_end = rhs_start + close_pos;
    
    IRStmt* stmt = ir_alloc_stmt(ir);
    stmt->lhs_index = var_index(lhs);
    stmt->source_line = line;
    stmt->source_column = col;
    strncpy(stmt->func_name, fname, MAX_NAME_LEN - 1);
    stmt->func_name[MAX_NAME_LEN - 1] = '\0';
    
    if (content_start < content_end) {
        if (parse_strict_arguments_enhanced(content_start, content_end, stmt, line, col + (int)(content_start - expr)) != 0) {
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
    int len = (int)strlen(line);
    while (len > 0 && isspace((unsigned char)line[len-1])) len--;
    if (len <= 0) return 0;
    if (is_comment_line_enhanced(line)) return 0;

    char* line_copy = arena_alloc_unlimited(len + 1);
    strncpy(line_copy, line, len);
    line_copy[len] = '\0';
    
    if (parse_expression_strict_enhanced(line_copy, len, ir, line_num, 1) != 0) {
        set_error_context(line_copy, len);
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
#if defined(_WIN32) || defined(_WIN64)
                UnmapViewOfFile(func_table[i].ptr);
                CloseHandle(func_table[i].mapped_bin_handle.map_handle);
                CloseHandle(func_table[i].mapped_bin_handle.file_handle);
#else
                munmap(func_table[i].ptr, func_table[i].len);
#endif
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

#if defined(_WIN32) && !defined(__GNUC__)
// Custom getline for MSVC
typedef long long ssize_t;
ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    size_t pos;
    int c;

    if (lineptr == NULL || stream == NULL || n == NULL) {
        errno = EINVAL;
        return -1;
    }

    c = fgetc(stream);
    if (c == EOF) {
        return -1;
    }

    if (*lineptr == NULL) {
        *lineptr = malloc(128);
        if (*lineptr == NULL) {
            return -1;
        }
        *n = 128;
    }

    pos = 0;
    while(c != EOF) {
        if (pos + 1 >= *n) {
            size_t new_size = *n + (*n >> 2);
            if (new_size < 128) {
                new_size = 128;
            }
            char *new_ptr = realloc(*lineptr, new_size);
            if (new_ptr == NULL) {
                return -1;
            }
            *lineptr = new_ptr;
            *n = new_size;
        }

        (*lineptr)[pos++] = c;
        if (c == '\n') {
            break;
        }
        c = fgetc(stream);
    }

    (*lineptr)[pos] = '\0';
    return pos;
}
#endif

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
        
        // Trim leading whitespace for logic check
        char* trimmed_line = line;
        while(*trimmed_line && isspace((unsigned char)*trimmed_line)) trimmed_line++;
        if (*trimmed_line == '\0') continue; // empty line

        if (buflen + (size_t)r + 1 > bufcap) {
            // This is problematic with arena allocator. Re-allocating is not an option.
            // Let's just make the initial buffer huge.
            // A better solution would be a linked list of buffers.
            // For now, let's assume one line block won't exceed arena default size.
            // A proper fix would be to not use arena for this temp buffer.
            set_error(ERR_MEM_ALLOC_FAILED, starting_line + lines, 0, "Statement block too large to buffer");
            free(line);
            return NULL;
        }
        memcpy(buf + buflen, line, (size_t)r);
        buflen += (size_t)r;
        
        // Count parentheses with escape awareness
        bool in_string = false;
        bool escaped = false;
        
        for (ssize_t i = 0; i < r; ++i) {
            char c = line[i];
            
            if (in_string) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') in_string = false;
            } else {
                if (c == '"') in_string = true;
                else if (c == '(') depth++;
                else if (c == ')') depth--;
                else if (c == '=' && depth == 0) have_eq = 1;
            }
        }
        if (depth <= 0 && have_eq) break;
    }
    free(line);
    if (buflen == 0) { *out_lines_read = lines; return NULL; }

    buf[buflen] = '\0';
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
    
    while (!feof(f)) {
        int consumed = 0;
        char *block = read_block_enhanced(f, &consumed, line_num);
        if (!block) {
            line_num += consumed; // Account for blank lines at EOF
            break;
        }
        
        if (parse_line_strict_enhanced(block, ir, line_num) == -1) {
            fclose(f);
            return NULL;
        }
        line_num += consumed;
    }
    fclose(f);
    
    if (ir->count == 0) {
        // Not an error, could be an empty file.
        // set_error(ERR_PARSE_SYNTAX, 0, 0, "No valid statements found in %s", path);
        // return NULL;
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

    // Execute initial statements
    executor_enhanced(ir->stmts, ir->count, env_array);

    if (dry_run_mode) return;

    // ----------------- Portable file monitoring -----------------
    time_t last_mod = 0;
    FILE_MOD_TIME(path, &last_mod);

    for (;;) {
        time_t current_mod = 0;
        FILE_MOD_TIME(path, &current_mod);

        if (current_mod > last_mod) {
            last_mod = current_mod;

            printf("Script changed, reloading...\n");

            // This is a simplified reload. A robust implementation would need
            // to re-initialize more state or handle memory more carefully.
            // For this example, we re-parse and re-execute.
            
            // Clear environment values
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
            } else {
                 fprintf(stderr, "Reload error: %s\n", last_error.message);
            }
        }

        sleep_ms(1000); // 1 second polling
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
    {"Unicode escapes", "\"\\u0048\\u0065\\u006C\\u006C\\x6F\"", "Hello", false, ERR_NONE},
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
        bool result = is_string_literal_enhanced(test->input, (int)strlen(test->input), 
                                               &processed, &len, 1, 1);
        
        if (test->should_fail) {
            if (!result || last_error.code == test->expected_error) {
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
        
        int result = parse_expression_strict_enhanced(valid_cases[i], (int)strlen(valid_cases[i]), 
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
        
        int result = parse_expression_strict_enhanced(invalid_cases[i], (int)strlen(invalid_cases[i]), 
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
        
        // Find the variable name from the index
        const char* lhs_name = "unknown";
        if (stmt->lhs_index >= 0 && stmt->lhs_index < var_count) {
           lhs_name = env_array[stmt->lhs_index]->name;
        }

        printf("  [%d] %s = %s(...) with %d args (line %d, col %d)\n", 
               i, lhs_name,
               stmt->func_name, stmt->argc, stmt->source_line, stmt->source_column);
        
        // Validate function exists
        size_t len;
        int arg_count;
        void* func_ptr = get_func_ptr(stmt->func_name, &arg_count, &len);
        if (!func_ptr) {
            printf("    WARNING: Function '%s' not found in %s\n", stmt->func_name, func_directory);
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
        fprintf(stderr, "  --fixed-vars=N         Set fixed variable pool size (default: %d)\n", DEFAULT_FIXED_VARS);
        fprintf(stderr, "  --table-size=N         Set hash table size (default: 4096)\n");
        fprintf(stderr, "  --func-dir=<path>      Set the directory for function binaries (default: funcs)\n");
        fprintf(stderr, "  --non-strict           Disable strict OPTIVAR mode\n");
        fprintf(stderr, "  --dry-run              Parse and validate without execution\n");
        fprintf(stderr, "  --test-escapes         Run escape sequence unit tests\n");
        fprintf(stderr, "  --test-strict          Run strict mode validation tests\n");
        fprintf(stderr, "  --test-all             Run all unit tests\n");
        fprintf(stderr, "  --preload              Preload all functions at startup\n");
        fprintf(stderr, "  --preload=list:a,b     Preload specific functions\n");
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
                // Round to next power of 2
                int power = 0;
                long temp = var_table_size;
                while(temp > 1) {
                    temp >>= 1;
                    power++;
                }
                var_table_size = 1 << (power + 1);

                fprintf(stderr, "Warning: table-size rounded to next power of two: %d\n", var_table_size);
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
    preload_binfuncs(func_directory);
    
    if (preload_all) {
        for (int i = 0; i < func_count; i++) {
            if (!func_table[i].ptr) {
                int ac; size_t len;
                func_table[i].ptr = load_binfunc(
                    func_table[i].name, &ac, &len, &func_table[i].mapped_bin_handle
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
                    int ac; size_t len;
                    func_table[i].ptr = load_binfunc(
                        func_table[i].name, &ac, &len, &func_table[i].mapped_bin_handle
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
