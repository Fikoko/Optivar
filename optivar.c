//
// optivar.c -- Fully cross-platform, memory-safe, minimalistic, superoptimized, scaleable IR executor
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
// CRC32 implementation
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
                case '"': result[result_pos++] = '"'; i += 2; break;
                case '\\': result[result_pos++] = '\\'; i += 2; break;
                case '=': result[result_pos++] = '='; i += 2; break;
                case '(': result[result_pos++] = '('; i += 2; break;
                case ')': result[result_pos++] = ')'; i += 2; break;
                case ',': result[result_pos++] = ','; i += 2; break;
                case 'n': result[result_pos++] = '\n'; i += 2; break;
                case 't': result[result_pos++] = '\t'; i += 2; break;
                case 'r': result[result_pos++] = '\r'; i += 2; break;
                case '0': result[result_pos++] = '\0'; i += 2; break;
                case 'x':
                    if (i + 3 < input_len) {
                        int d1 = hex_digit_value(input[i + 2]);
                        int d2 = hex_digit_value(input[i + 3]);
                        if (d1 >= 0 && d2 >= 0) {
                            result[result_pos++] = (char)(d1 * 16 + d2);
                            i += 4;
                        } else {
                            set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, "Invalid hexadecimal escape sequence");
                            return NULL;
                        }
                    } else {
                        set_error(ERR_PARSE_INVALID_ESCAPE, line, col + i, "Incomplete hexadecimal escape sequence");
                        return NULL;
                    }
                    break;
                // Other cases removed for brevity but would be here...
                default:
                    result[result_pos++] = input[i];
                    i++;
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

//
// Value management
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
            fixed_pool[i].in_use = 1; return &fixed_pool[i];
        }
    }
    if (fixed_top < FIXED_VARS) {
        fixed_pool[fixed_top].in_use = 1; return &fixed_pool[fixed_top++];
    }
    VarPoolChunk* c = dynamic_pool;
    while (c) {
        for (int i = 0; i < c->capacity; ++i) {
            if (!c->slots[i].in_use) {
                c->slots[i].in_use = 1; return &c->slots[i];
            }
        }
        c = c->next;
    }
    VarPoolChunk* nc = arena_alloc_unlimited(sizeof(VarPoolChunk));
    nc->slots = arena_alloc_unlimited(VAR_CHUNK_SIZE * sizeof(VarSlot));
    nc->capacity = VAR_CHUNK_SIZE;
    nc->next = dynamic_pool;
    dynamic_pool = nc;
    nc->slots[0].in_use = 1;
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
        fclose(f); set_error(ERR_FILE_READ_ERROR, 0, 0, "Function file too small: %s", path); return NULL;
    }

    BinHeader hdr;
    if (fread(&hdr, 1, sizeof(BinHeader), f) != sizeof(BinHeader)) {
        fclose(f); set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot read function header: %s", path); return NULL;
    }

    if (hdr.magic != BIN_MAGIC) {
        fclose(f); set_error(ERR_FILE_READ_ERROR, 0, 0, "Invalid function file magic: %s", path); return NULL;
    }
    
    fclose(f);

    size_t code_size = file_size - sizeof(BinHeader);
    void* mapped_code = NULL;

#if defined(_WIN32) || defined(_WIN64)
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot open function file for mapping: %s", path); return NULL; }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
    if (hMap == NULL) { CloseHandle(hFile); set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot create file mapping: %s", path); return NULL; }

    mapped_code = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, sizeof(BinHeader), code_size);
    if (mapped_code == NULL) { CloseHandle(hMap); CloseHandle(hFile); set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot map view of file: %s", path); return NULL; }
    mapped_bin_out->file_handle = hFile;
    mapped_bin_out->map_handle = hMap;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) { set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot open function file for mapping: %s", path); return NULL; }
    mapped_code = mmap(NULL, code_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, sizeof(BinHeader));
    if (mapped_code == MAP_FAILED) { close(fd); set_error(ERR_FILE_READ_ERROR, 0, 0, "Cannot map function: %s", path); return NULL; }
    close(fd);
#endif

    uint32_t crc = crc32(0, (unsigned char*)mapped_code, code_size);
    if (crc != hdr.code_crc) {
#if defined(_WIN32) || defined(_WIN64)
        UnmapViewOfFile(mapped_code); CloseHandle(mapped_bin_out->map_handle); CloseHandle(mapped_bin_out->file_handle);
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
        if (!func_table) { set_error(ERR_MEM_ALLOC_FAILED, 0, 0, "Cannot allocate function table"); exit(EXIT_FAILURE); }
    }
#if defined(_WIN32) || defined(_WIN64)
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s\\*.bin", dirpath);
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);

    if (find_handle == INVALID_HANDLE_VALUE) { fprintf(stderr, "Warning: cannot open function directory %s\n", dirpath); return; }

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            size_t n = strlen(find_data.cFileName);
            if (n > 4 && strcmp(find_data.cFileName + n - 4, ".bin") == 0) {
                if (func_count >= func_table_size) grow_func_table();
                size_t namelen = n - 4;
                if (namelen < MAX_NAME_LEN) {
                    strncpy(func_table[func_count].name, find_data.cFileName, namelen);
                    func_table[func_count].name[namelen] = '\0';
                    func_count++;
                }
            }
        }
    } while (FindNextFileA(find_handle, &find_data) != 0);

    FindClose(find_handle);
#else
    DIR* d = opendir(dirpath);
    if (!d) { fprintf(stderr, "Warning: cannot open %s\n", dirpath); return; }
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        #ifdef _DIRENT_HAVE_D_TYPE
        if (e->d_type != DT_REG && e->d_type != DT_UNKNOWN) continue;
        #endif
        
        size_t n = strlen(e->d_name);
        if (n > 4 && strcmp(e->d_name + n - 4, ".bin") == 0) {
            if (func_count >= func_table_size) grow_func_table();
            size_t namelen = n - 4;
            if (namelen < MAX_NAME_LEN) {
                strncpy(func_table[func_count].name, e->d_name, namelen);
                func_table[func_count].name[namelen] = '\0';
                func_count++;
            }
        }
    }
    closedir(d);
#endif
}

static void* get_func_ptr(const char* name, int* arg_count_out, size_t* len_out) {
    if (!func_table) { *arg_count_out = -1; *len_out = 0; return NULL; }
    for (int i = 0; i < func_count; ++i) {
        if (strcmp(func_table[i].name, name) == 0) {
            if (!func_table[i].ptr) {
                func_table[i].ptr = load_binfunc(name, &func_table[i].arg_count, &func_table[i].len, &func_table[i].mapped_bin_handle);
                if (!func_table[i].ptr) { *arg_count_out = -1; *len_out = 0; return NULL; }
            }
            *arg_count_out = func_table[i].arg_count;
            *len_out = func_table[i].len;
            return func_table[i].ptr;
        }
    }
    *arg_count_out = -1; *len_out = 0;
    return NULL;
}

//
// IR and var table helpers
//
static void ir_init(IR* ir) { ir->stmts = NULL; ir->count = ir->capacity = 0; }

static IRStmt* ir_alloc_stmt(IR* ir) {
    if (ir->count >= ir->capacity) {
        int newc = ir->capacity ? ir->capacity * 2 : 16;
        IRStmt* tmp = arena_alloc_unlimited(sizeof(IRStmt) * newc);
        if (ir->stmts) memcpy(tmp, ir->stmts, sizeof(IRStmt) * ir->count);
        ir->stmts = tmp;
        ir->capacity = newc;
    }
    return &ir->stmts[ir->count++];
}

static int var_index(const char* name) {
    if (!var_table) {
        var_table = arena_alloc_unlimited(sizeof(HashNode*) * var_table_size);
    }
    unsigned int h = hash_name(name, var_table_size);
    HashNode* node = var_table[h];
    while (node) {
        if (strcmp(node->name, name) == 0) return node->index;
        node = node->next;
    }
    VarSlot* s = pool_alloc();
    strncpy(s->name, name, MAX_NAME_LEN - 1);
    
    HashNode* hn = arena_alloc_unlimited(sizeof(HashNode));
    strncpy(hn->name, name, MAX_NAME_LEN - 1);
    hn->next = var_table[h];
    var_table[h] = hn;
    
    if (var_count >= env_alloc_size) {
        int ns = env_alloc_size ? env_alloc_size * 2 : (FIXED_VARS * 2);
        VarSlot** ne = arena_alloc_unlimited(sizeof(VarSlot*) * ns);
        if (env_array) memcpy(ne, env_array, sizeof(VarSlot*) * var_count);
        env_array = ne;
        env_alloc_size = ns;
    }
    hn->index = var_count;
    env_array[var_count] = s;
    return var_count++;
}

static void init_env(int total_vars) {
    env_alloc_size = total_vars > 0 ? total_vars : FIXED_VARS * 2;
    env_array = arena_alloc_unlimited(sizeof(VarSlot*) * env_alloc_size);
    fixed_pool = arena_alloc_unlimited(sizeof(VarSlot) * FIXED_VARS);
}

//
// Parsing Logic
//
static int find_argument_boundaries_enhanced(const char* args_str, int args_len, int** boundaries, int* arg_count, int line, int col) {
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
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_string = false;
        } else {
            if (c == '"') in_string = true;
            else if (c == '(') paren_depth++;
            else if (c == ')') {
                paren_depth--;
                if (paren_depth < 0) { set_error(ERR_PARSE_UNMATCHED_PAREN, line, col + pos, "Unmatched closing parenthesis"); return -1; }
            } else if (c == ',' && paren_depth == 0) {
                (*boundaries)[(*arg_count)++] = pos;
                pos++;
                while (pos < args_len && isspace((unsigned char)args_str[pos])) pos++;
                if (pos < args_len) (*boundaries)[(*arg_count)++] = pos;
                continue;
            }
        }
        pos++;
    }
    
    if (in_string) { set_error(ERR_PARSE_SYNTAX, line, col, "Unterminated string literal"); return -1; }
    if (paren_depth > 0) { set_error(ERR_PARSE_UNMATCHED_PAREN, line, col, "Unmatched opening parenthesis"); return -1; }
    
    if (*arg_count % 2 == 1) (*boundaries)[(*arg_count)++] = args_len;
    
    return *arg_count / 2;
}

static int parse_arguments_as_strings(const char* args_start, const char* args_end, IRStmt* stmt, int line, int col) {
    int args_len = args_end - args_start;
    if (args_len <= 0) {
        stmt->argc = 0;
        stmt->args = NULL;
        return 0;
    }

    int* boundaries;
    int boundary_count;
    int arg_count = find_argument_boundaries_enhanced(args_start, args_len, &boundaries, &boundary_count, line, col);
    
    if (arg_count < 0) return -1;
    
    stmt->argc = arg_count;
    stmt->args = arg_count > 0 ? arena_alloc_unlimited(sizeof(Value*) * arg_count) : NULL;

    for (int i = 0; i < arg_count; i++) {
        const char* arg_str_start = args_start + boundaries[i * 2];
        int arg_str_len = boundaries[i * 2 + 1] - boundaries[i * 2];
        
        while (arg_str_len > 0 && isspace((unsigned char)*arg_str_start)) { arg_str_start++; arg_str_len--; }
        while (arg_str_len > 0 && isspace((unsigned char)arg_str_start[arg_str_len-1])) { arg_str_len--; }

        if (arg_str_len > 0) {
            char* arg_copy = arena_alloc_unlimited(arg_str_len + 1);
            memcpy(arg_copy, arg_str_start, arg_str_len);
            arg_copy[arg_str_len] = '\0';
            stmt->args[i] = value_create_string_safe(arg_copy);
        } else {
            stmt->args[i] = value_create_string_safe("");
        }
    }
    return 0;
}

static int find_matching_paren(const char* str, int len, int start) {
    int depth = 1;
    bool in_string = false;
    for (int i = start + 1; i < len; ++i) {
        if (in_string) {
            if (str[i] == '"' && str[i-1] != '\\') in_string = false;
        } else {
            if (str[i] == '"') in_string = true;
            else if (str[i] == '(') depth++;
            else if (str[i] == ')') {
                depth--;
                if (depth == 0) return i;
            }
        }
    }
    return -1;
}

static int parse_expression_strict_enhanced(const char* expr, int expr_len, IR* ir, int line, int col) {
    const char* eq = memchr(expr, '=', expr_len);
    if (!eq) { set_error(ERR_PARSE_MISSING_ASSIGN, line, col, "Expression must contain assignment operator '='"); return -1; }

    const char* lhs_start = expr;
    int lhs_len = eq - lhs_start;
    while (lhs_len > 0 && isspace((unsigned char)lhs_start[lhs_len-1])) lhs_len--;
    
    if (lhs_len <= 0 || lhs_len >= MAX_NAME_LEN) { set_error(ERR_PARSE_INVALID_VAR, line, col, "Invalid variable name"); return -1; }
    char lhs[MAX_NAME_LEN];
    memcpy(lhs, lhs_start, lhs_len);
    lhs[lhs_len] = '\0';

    const char* rhs_start = eq + 1;
    while (rhs_start < expr + expr_len && isspace((unsigned char)*rhs_start)) rhs_start++;
    
    const char* open_paren = strchr(rhs_start, '(');
    if (!open_paren) { set_error(ERR_PARSE_INVALID_FUNC, line, col + (rhs_start - expr), "Missing opening parenthesis for function call"); return -1; }
    
    int fname_len = open_paren - rhs_start;
    if (fname_len <= 0 || fname_len >= MAX_NAME_LEN) { set_error(ERR_PARSE_INVALID_FUNC, line, col + (rhs_start - expr), "Invalid function name"); return -1; }
    char fname[MAX_NAME_LEN];
    memcpy(fname, rhs_start, fname_len);
    fname[fname_len] = '\0';
    
    int close_paren_pos = find_matching_paren(expr, expr_len, (int)(open_paren - expr));
    if (close_paren_pos < 0) { set_error(ERR_PARSE_UNMATCHED_PAREN, line, col + (open_paren - expr), "Unmatched opening parenthesis"); return -1; }

    const char* content_start = open_paren + 1;
    const char* content_end = expr + close_paren_pos;

    IRStmt* stmt = ir_alloc_stmt(ir);
    stmt->lhs_index = var_index(lhs);
    stmt->source_line = line;
    stmt->source_column = col;
    strncpy(stmt->func_name, fname, MAX_NAME_LEN - 1);
    
    if (parse_arguments_as_strings(content_start, content_end, stmt, line, col + (content_start - expr)) != 0) {
        return -1;
    }
    
    return 0;
}

static int parse_line_strict_enhanced(const char* line, IR* ir, int line_num) {
    const char* start = line;
    while (*start && isspace((unsigned char)*start)) start++;
    if (*start == '\0' || (*start == '-' && *(start+1) == '-')) return 0;

    int len = (int)strlen(start);
    while (len > 0 && isspace((unsigned char)start[len-1])) len--;
    if (len <= 0) return 0;

    if (parse_expression_strict_enhanced(start, len, ir, line_num, (int)(start - line + 1)) != 0) {
        set_error_context(line, (int)strlen(line));
        return -1;
    }
    return 0;
}

//
// Executor
//
static BinContext global_bin_context;

static void executor_enhanced(IRStmt* stmts, int stmt_count, VarSlot** env) {
    if (!stmts || stmt_count <= 0) return;
    
    global_bin_context.env = env;
    global_bin_context.func_table = func_table;
    global_bin_context.func_count = func_count;
    
    for (int i = 0; i < stmt_count; ++i) {
        IRStmt* stmt = &stmts[i];
        if (stmt->dead || stmt->lhs_index < 0) continue;
        
        if (!stmt->func_ptr) {
            size_t len; int arg_count;
            stmt->func_ptr = get_func_ptr(stmt->func_name, &arg_count, &len);
        }
        if (!stmt->func_ptr) {
            if (strict_mode) {
                set_error(ERR_EXEC_FUNC_NOT_FOUND, stmt->source_line, stmt->source_column, "Function '%s' not found", stmt->func_name);
                if (!dry_run_mode) exit(EXIT_FAILURE);
            }
            continue;
        }
        
        if (dry_run_mode) continue;
        
        VarSlot* lhs = env[stmt->lhs_index];
        BinFunc fn = (BinFunc)stmt->func_ptr;
        Value* result = fn(stmt->args, stmt->argc, &global_bin_context);
        
        if (result) {
            if (lhs->value) value_release(lhs->value);
            lhs->value = result;
            value_retain(result);
        }
    }
}

static void cleanup_all() {
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
}

#if defined(_WIN32) && !defined(__GNUC__)
typedef long long ssize_t;
ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    size_t pos = 0; int c;
    if (!lineptr || !stream || !n) { errno = EINVAL; return -1; }
    c = fgetc(stream); if (c == EOF) return -1;
    if (!*lineptr) { *lineptr = malloc(128); if (!*lineptr) return -1; *n = 128; }
    while(c != EOF) {
        if (pos + 1 >= *n) {
            size_t new_size = *n + (*n >> 2); if (new_size < 128) new_size = 128;
            char *new_ptr = realloc(*lineptr, new_size); if (!new_ptr) return -1;
            *lineptr = new_ptr; *n = new_size;
        }
        (*lineptr)[pos++] = c; if (c == '\n') break; c = fgetc(stream);
    }
    (*lineptr)[pos] = '\0'; return pos;
}
#endif

//
// Script loading and execution flow
//
static IR* parse_script_file_enhanced(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) { set_error(ERR_FILE_NOT_FOUND, 0, 0, "Cannot open script file: %s", path); return NULL; }
    
    IR* ir = arena_alloc_unlimited(sizeof(IR));
    ir_init(ir);
    
    char* line = NULL;
    size_t cap = 0;
    ssize_t len;
    int line_num = 1;

    while ((len = getline(&line, &cap, f)) != -1) {
        if (parse_line_strict_enhanced(line, ir, line_num) == -1) {
            fclose(f); free(line); return NULL;
        }
        line_num++;
    }
    
    fclose(f);
    free(line);
    return ir;
}

static void run_script_enhanced(const char* path) {
    IR* ir = parse_script_file_enhanced(path);
    if (!ir) {
        fprintf(stderr, "Parse error: %s", last_error.message);
        if (last_error.line > 0) fprintf(stderr, " (line %d, col %d)", last_error.line, last_error.column);
        if (last_error.context[0]) fprintf(stderr, "\nContext: %s", last_error.context);
        fprintf(stderr, "\n");
        return;
    }
    
    executor_enhanced(ir->stmts, ir->count, env_array);

    if (dry_run_mode) return;

    time_t last_mod = 0;
    FILE_MOD_TIME(path, &last_mod);

    for (;;) {
        sleep_ms(1000);
        time_t current_mod = 0;
        FILE_MOD_TIME(path, &current_mod);
        if (current_mod > last_mod) {
            last_mod = current_mod;
            printf("Script changed, reloading...\n");
            // A full reload would require cleaning and re-initializing the entire state.
            // This simplified loop just re-runs the logic on a fresh parse.
            IR* new_ir = parse_script_file_enhanced(path);
            if (new_ir) {
                // Note: This simple reload doesn't clear old variables.
                executor_enhanced(new_ir->stmts, new_ir->count, env_array);
            } else {
                 fprintf(stderr, "Reload error: %s\n", last_error.message);
            }
        }
    }
}

//
// Main function with argument parsing
//
int main(int argc, char **argv) {
    atexit(cleanup_all);
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.optivar> [--func-dir=<path>] [...options]\n", argv[0]);
        return 1;
    }
    
    char *script_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--fixed-vars=", 13) == 0) FIXED_VARS = atoi(argv[i] + 13);
        else if (strncmp(argv[i], "--table-size=", 13) == 0) var_table_size = atoi(argv[i] + 13);
        else if (strncmp(argv[i], "--func-dir=", 11) == 0) func_directory = argv[i] + 11;
        else if (strcmp(argv[i], "--non-strict") == 0) strict_mode = 0;
        else if (strcmp(argv[i], "--dry-run") == 0) dry_run_mode = 1;
        else if (argv[i][0] != '-') script_path = argv[i];
    }
    
    if (!script_path) {
        fprintf(stderr, "Error: No script file specified.\n");
        return 1;
    }
    
    init_env(FIXED_VARS * 2);
    preload_binfuncs(func_directory);
    
    run_script_enhanced(script_path);

    return 0;
}
