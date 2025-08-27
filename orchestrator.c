// orchestrator.c
// Generic Optivar orchestrator with Variant type and binary-function ABI.
//
// Compile:
//   gcc -std=c11 -O2 -Wall orchestrator.c -o orchestrator
//
// Usage:
//   ./orchestrator program.optv
//
// Notes:
// - Binary functions must follow the ABI: Var* func(Var** args, int count)
//   and return a heap-allocated Var* (caller takes ownership).
// - Binaries are loaded from binfuncs/<name>.bin and cached (mmap'd).
//

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef enum {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING,
    TYPE_BOOL,
    TYPE_ARRAY,
    TYPE_OBJECT,
    TYPE_FUNCTION,
    TYPE_NULL
} VarType;

typedef struct Var {
    char* name;      // optional name (NULL for anonymous values)
    VarType type;
    union {
        long long i_val;
        double f_val;
        char* s_val;
        int b_val;
        struct {
            struct Var** items;
            int count;
            int capacity;
        } array;
        struct {
            char** keys;
            struct Var** values;
            int count;
            int capacity;
        } object;
        void* func_ptr; // raw pointer for function references
    } data;
} Var;

typedef struct {
    Var** vars;
    int count;
    int capacity;
} Env;

// ---- Function loader cache ----
typedef struct {
    char* name;
    void* ptr;
    size_t size;
} LoadedFunc;

static LoadedFunc* func_cache = NULL;
static int func_cache_count = 0;
static int func_cache_capacity = 0;

// ---- Helper utilities ----
static char* strtrim(char* s) {
    if(!s) return s;
    while(isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s) - 1;
    while(end >= s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static char* strdup_safe(const char* s) {
    if(!s) return NULL;
    char* r = malloc(strlen(s) + 1);
    if(!r) { perror("malloc"); exit(1); }
    strcpy(r, s);
    return r;
}

// ---- Var constructors / destructor / clone ----
static Var* var_new() {
    Var* v = calloc(1, sizeof(Var));
    if(!v) { perror("calloc"); exit(1); }
    v->type = TYPE_NULL;
    return v;
}

static Var* var_from_int(long long i) {
    Var* v = var_new();
    v->type = TYPE_INT;
    v->data.i_val = i;
    return v;
}

static Var* var_from_float(double f) {
    Var* v = var_new();
    v->type = TYPE_FLOAT;
    v->data.f_val = f;
    return v;
}

static Var* var_from_string(const char* s) {
    Var* v = var_new();
    v->type = TYPE_STRING;
    v->data.s_val = strdup_safe(s);
    return v;
}

static Var* var_from_bool(int b) {
    Var* v = var_new();
    v->type = TYPE_BOOL;
    v->data.b_val = b ? 1 : 0;
    return v;
}

static Var* var_null() {
    return var_new();
}

static Var* var_clone(const Var* src) {
    if(!src) return NULL;
    Var* v = var_new();
    v->type = src->type;
    if(src->name) v->name = strdup_safe(src->name);
    switch(src->type) {
        case TYPE_INT:  v->data.i_val = src->data.i_val; break;
        case TYPE_FLOAT: v->data.f_val = src->data.f_val; break;
        case TYPE_STRING: v->data.s_val = strdup_safe(src->data.s_val); break;
        case TYPE_BOOL: v->data.b_val = src->data.b_val; break;
        case TYPE_NULL: break;
        case TYPE_FUNCTION: v->data.func_ptr = src->data.func_ptr; break;
        case TYPE_ARRAY:
            if(src->data.array.count > 0) {
                v->data.array.count = src->data.array.count;
                v->data.array.capacity = src->data.array.count;
                v->data.array.items = calloc(v->data.array.capacity, sizeof(Var*));
                for(int i=0;i<src->data.array.count;i++) v->data.array.items[i] = var_clone(src->data.array.items[i]);
            }
            break;
        case TYPE_OBJECT:
            if(src->data.object.count > 0) {
                v->data.object.count = src->data.object.count;
                v->data.object.capacity = src->data.object.count;
                v->data.object.keys = calloc(v->data.object.capacity, sizeof(char*));
                v->data.object.values = calloc(v->data.object.capacity, sizeof(Var*));
                for(int i=0;i<src->data.object.count;i++) {
                    v->data.object.keys[i] = strdup_safe(src->data.object.keys[i]);
                    v->data.object.values[i] = var_clone(src->data.object.values[i]);
                }
            }
            break;
    }
    return v;
}

static void var_free(Var* v) {
    if(!v) return;
    if(v->name) free(v->name);
    switch(v->type) {
        case TYPE_STRING:
            if(v->data.s_val) free(v->data.s_val);
            break;
        case TYPE_ARRAY:
            for(int i=0;i<v->data.array.count;i++) var_free(v->data.array.items[i]);
            free(v->data.array.items);
            break;
        case TYPE_OBJECT:
            for(int i=0;i<v->data.object.count;i++) {
                free(v->data.object.keys[i]);
                var_free(v->data.object.values[i]);
            }
            free(v->data.object.keys);
            free(v->data.object.values);
            break;
        default: break;
    }
    free(v);
}

// ---- Environment operations ----
static void env_init(Env* e) {
    e->vars = NULL;
    e->count = 0;
    e->capacity = 0;
}

static Var* env_get(Env* e, const char* name) {
    if(!name) return NULL;
    for(int i=0;i<e->count;i++) {
        if(e->vars[i]->name && strcmp(e->vars[i]->name, name) == 0) return e->vars[i];
    }
    return NULL;
}

// Inserts or replaces; takes ownership of value (value should be heap-allocated)
static void env_set(Env* e, const char* name, Var* value) {
    if(!name || !value) return;
    Var* existing = env_get(e, name);
    if(existing) {
        // replace
        if(existing->type == TYPE_STRING && existing->data.s_val) { /* freed by var_free */ }
        var_free(existing);
        // put new value in same slot
        value->name = strdup_safe(name);
        // replace pointer in array
        for(int i=0;i<e->count;i++) {
            if(e->vars[i] && e->vars[i]->name && strcmp(e->vars[i]->name, name) == 0) {
                e->vars[i] = value;
                return;
            }
        }
    }

    // append
    if(e->count >= e->capacity) {
        e->capacity = e->capacity ? e->capacity * 2 : 8;
        e->vars = realloc(e->vars, e->capacity * sizeof(Var*));
        if(!e->vars) { perror("realloc"); exit(1); }
    }
    value->name = strdup_safe(name);
    e->vars[e->count++] = value;
}

static void env_free(Env* e) {
    if(!e) return;
    for(int i=0;i<e->count;i++) var_free(e->vars[i]);
    free(e->vars);
    e->vars = NULL;
    e->count = e->capacity = 0;
}

// ---- Printing ----
static void print_var(const Var* v);

static void print_var(const Var* v) {
    if(!v) { printf("null"); return; }
    switch(v->type) {
        case TYPE_INT: printf("%lld", (long long)v->data.i_val); break;
        case TYPE_FLOAT: printf("%g", v->data.f_val); break;
        case TYPE_STRING: printf("\"%s\"", v->data.s_val ? v->data.s_val : ""); break;
        case TYPE_BOOL: printf(v->data.b_val ? "true" : "false"); break;
        case TYPE_NULL: printf("null"); break;
        case TYPE_FUNCTION: printf("<function>"); break;
        case TYPE_ARRAY:
            printf("[");
            for(int i=0;i<v->data.array.count;i++) {
                print_var(v->data.array.items[i]);
                if(i < v->data.array.count - 1) printf(", ");
            }
            printf("]");
            break;
        case TYPE_OBJECT:
            printf("{");
            for(int i=0;i<v->data.object.count;i++) {
                printf("\"%s\": ", v->data.object.keys[i]);
                print_var(v->data.object.values[i]);
                if(i < v->data.object.count - 1) printf(", ");
            }
            printf("}");
            break;
    }
}

// ---- Binary loader and cache ----
static void* load_binary_nocache(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if(!f) {
        // perror intentionally deferred to caller
        return NULL;
    }
    if(fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long len = ftell(f);
    if(len < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    // allocate executable mmap
    void* buffer = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(buffer == MAP_FAILED) { fclose(f); return NULL; }
    size_t nread = fread(buffer, 1, len, f);
    fclose(f);
    if(nread != (size_t)len) {
        munmap(buffer, len);
        return NULL;
    }
    *out_size = len;
    return buffer;
}

static void cache_add(const char* name, void* ptr, size_t size) {
    if(func_cache_count >= func_cache_capacity) {
        func_cache_capacity = func_cache_capacity ? func_cache_capacity * 2 : 8;
        func_cache = realloc(func_cache, func_cache_capacity * sizeof(LoadedFunc));
        if(!func_cache) { perror("realloc"); exit(1); }
    }
    func_cache[func_cache_count].name = strdup_safe(name);
    func_cache[func_cache_count].ptr = ptr;
    func_cache[func_cache_count].size = size;
    func_cache_count++;
}

static void* cache_get(const char* name, size_t* out_size) {
    for(int i=0;i<func_cache_count;i++) {
        if(strcmp(func_cache[i].name, name) == 0) {
            if(out_size) *out_size = func_cache[i].size;
            return func_cache[i].ptr;
        }
    }
    return NULL;
}

static void cache_cleanup() {
    for(int i=0;i<func_cache_count;i++) {
        if(func_cache[i].ptr && func_cache[i].size > 0) {
            munmap(func_cache[i].ptr, func_cache[i].size);
        }
        free(func_cache[i].name);
    }
    free(func_cache);
    func_cache = NULL;
    func_cache_count = func_cache_capacity = 0;
}

// Function ABI: Var* func(Var** args, int count)
typedef Var* (*varfunc_t)(Var** args, int count);

static Var* execute_func(Env* env, const char* func_name, Var** args, int arg_count) {
    char path[512];
    snprintf(path, sizeof(path), "binfuncs/%s.bin", func_name);

    size_t size = 0;
    void* fptr = cache_get(func_name, &size);
    if(!fptr) {
        fptr = load_binary_nocache(path, &size);
        if(!fptr) {
            fprintf(stderr, "Error: could not load function binary '%s' (%s)\n", path, strerror(errno));
            return var_null();
        }
        cache_add(func_name, fptr, size);
    }

    varfunc_t f = (varfunc_t)fptr;
    Var* res = f(args, arg_count);
    if(!res) {
        // treat as null result
        return var_null();
    }
    return res; // ownership to caller
}

// ---- Parsing literals and args ----
static int is_integer_literal(const char* s) {
    if(!s || *s == '\0') return 0;
    const char* p = s;
    if(*p == '+' || *p == '-') p++;
    if(!isdigit((unsigned char)*p)) return 0;
    while(*p) {
        if(!isdigit((unsigned char)*p)) return 0;
        p++;
    }
    return 1;
}

static int looks_like_float(const char* s) {
    if(!s) return 0;
    int dot = 0;
    const char* p = s;
    if(*p == '+' || *p == '-') p++;
    int digits = 0;
    while(*p) {
        if(*p == '.') {
            if(dot) return 0;
            dot = 1;
        } else if(isdigit((unsigned char)*p)) {
            digits = 1;
        } else return 0;
        p++;
    }
    return dot && digits;
}

// parse token into a heap-allocated Var*.
// If token is a variable name, resolve from env and return a clone of the env var (so functions can mutate safely).
static Var* parse_token_to_var(Env* env, char* token) {
    char* t = strtrim(token);
    int len = t ? strlen(t) : 0;
    if(!t || len == 0) return var_null();

    // quoted string
    if(t[0] == '"' && t[len-1] == '"' && len >= 2) {
        // remove quotes inside
        char tmp[len-1];
        memcpy(tmp, t+1, len-2);
        tmp[len-2] = '\0';
        return var_from_string(tmp);
    }

    // booleans/null
    if(strcmp(t, "true") == 0) return var_from_bool(1);
    if(strcmp(t, "false") == 0) return var_from_bool(0);
    if(strcmp(t, "null") == 0) return var_null();

    // integers and floats
    if(is_integer_literal(t)) {
        long long vv = atoll(t);
        return var_from_int(vv);
    }
    if(looks_like_float(t)) {
        double vf = atof(t);
        return var_from_float(vf);
    }

    // otherwise treat as variable name: look up in env
    Var* found = env_get(env, t);
    if(found) {
        return var_clone(found);
    } else {
        fprintf(stderr, "Warning: variable '%s' not found; using null\n", t);
        return var_null();
    }
}

// split args string by commas (handles simple cases; does not parse nested arrays/objects)
static Var** parse_args(Env* env, char* argstr, int* out_count) {
    Var** args = NULL;
    int count = 0;
    int cap = 0;
    if(!argstr || strlen(argstr) == 0) { *out_count = 0; return NULL; }

    char* saveptr = NULL;
    char* token = strtok_r(argstr, ",", &saveptr);
    while(token) {
        Var* v = parse_token_to_var(env, token);
        if(count >= cap) {
            cap = cap ? cap * 2 : 8;
            args = realloc(args, cap * sizeof(Var*));
            if(!args) { perror("realloc"); exit(1); }
        }
        args[count++] = v;
        token = strtok_r(NULL, ",", &saveptr);
    }
    *out_count = count;
    return args;
}

// ---- Program runner ----
static void run_program(const char* filename, Env* env) {
    FILE* f = fopen(filename, "r");
    if(!f) { perror("fopen"); exit(1); }
    if(fseek(f, 0, SEEK_END) != 0) { fclose(f); perror("fseek"); exit(1); }
    long len = ftell(f);
    if(len < 0) { fclose(f); perror("ftell"); exit(1); }
    fseek(f, 0, SEEK_SET);

    char* buf = malloc(len + 1);
    if(!buf) { perror("malloc"); exit(1); }
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    buf[r] = '\0';

    // split by ';'
    char* saveptr = NULL;
    char* stmt = strtok_r(buf, ";", &saveptr);
    while(stmt) {
        char* s = strtrim(stmt);
        if(!s || strlen(s) == 0) { stmt = strtok_r(NULL, ";", &saveptr); continue; }

        // find '=' separator
        char* eq = strchr(s, '=');
        if(!eq) {
            fprintf(stderr, "Parse error: statement missing '=' -> '%s'\n", s);
            stmt = strtok_r(NULL, ";", &saveptr); continue;
        }
        *eq = '\0';
        char* lhs = strtrim(s);
        char* rhs = strtrim(eq + 1);

        // parse rhs as func(args) or literal
        // check for func(...). find '('
        char* popen = strchr(rhs, '(');
        char* pclose = NULL;
        char funcname[256];
        char* args_str = NULL;

        if(popen) {
            pclose = strrchr(rhs, ')');
            if(!pclose) {
                fprintf(stderr, "Parse error: missing ')' in '%s'\n", rhs);
                stmt = strtok_r(NULL, ";", &saveptr); continue;
            }
            // func name is substring before '('
            int fname_len = popen - rhs;
            if(fname_len >= (int)sizeof(funcname)) fname_len = sizeof(funcname)-1;
            strncpy(funcname, rhs, fname_len);
            funcname[fname_len] = '\0';
            strtrim(funcname);

            // args substring
            int alen = pclose - (popen + 1);
            args_str = malloc(alen + 1);
            if(!args_str) { perror("malloc"); exit(1); }
            memcpy(args_str, popen + 1, alen);
            args_str[alen] = '\0';
        } else {
            // rhs is literal or variable -> assign directly
            Var* v = parse_token_to_var(env, rhs);
            env_set(env, lhs, v);
            stmt = strtok_r(NULL, ";", &saveptr);
            continue;
        }

        // parse args into Var**
        int arg_count = 0;
        Var** args = parse_args(env, args_str, &arg_count);

        // execute function
        Var* result = execute_func(env, funcname, args, arg_count);

        // store result in environment (take ownership)
        env_set(env, lhs, result);

        // cleanup args list (they were clones/heap allocated)
        for(int i=0;i<arg_count;i++) var_free(args[i]);
        free(args);
        free(args_str);

        stmt = strtok_r(NULL, ";", &saveptr);
    }

    free(buf);
}

// ---- Main ----
int main(int argc, char** argv) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s file.optv\n", argv[0]);
        return 1;
    }

    Env env;
    env_init(&env);

    run_program(argv[1], &env);

    printf("Environment:\n");
    for(int i=0;i<env.count;i++) {
        printf("%s = ", env.vars[i]->name ? env.vars[i]->name : "(anon)");
        print_var(env.vars[i]);
        printf("\n");
    }

    env_free(&env);
    cache_cleanup();
    return 0;
}
