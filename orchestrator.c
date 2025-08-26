#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

// Dynamic variable structure
typedef struct {
    char* name;  // dynamically allocated variable name
    int value;   // variable value
} Var;

typedef struct {
    Var* vars;      // dynamic array of variables
    int count;      // number of variables used
    int capacity;   // current allocated capacity
} Env;

// Retrieve variable value
int env_get(Env* env, const char* name) {
    for(int i = 0; i < env->count; i++)
        if(strcmp(env->vars[i].name, name) == 0)
            return env->vars[i].value;
    fprintf(stderr, "Error: variable %s not found\n", name);
    exit(1);
}

// Add or update variable
void env_set(Env* env, const char* name, int value) {
    for(int i = 0; i < env->count; i++) {
        if(strcmp(env->vars[i].name, name) == 0) {
            env->vars[i].value = value;
            return;
        }
    }

    // grow array if needed
    if(env->count >= env->capacity) {
        env->capacity = env->capacity ? env->capacity * 2 : 4;
        env->vars = realloc(env->vars, env->capacity * sizeof(Var));
        if(!env->vars) { perror("realloc"); exit(1); }
    }

    env->vars[env->count].name = malloc(strlen(name) + 1);
    if(!env->vars[env->count].name) { perror("malloc"); exit(1); }
    strcpy(env->vars[env->count].name, name);
    env->vars[env->count].value = value;
    env->count++;
}

// Free all dynamically allocated variable names
void env_free(Env* env) {
    for(int i=0; i<env->count; i++)
        free(env->vars[i].name);
    free(env->vars);
}

// Load binary function into executable memory
void* load_binary(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if(!f) { perror("fopen"); exit(1); }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* buffer = mmap(NULL, *size,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(!buffer) { perror("mmap"); exit(1); }

    fread(buffer, 1, *size, f);
    fclose(f);
    return buffer;
}

// Call function with unlimited arguments
typedef int (*varfunc_t)(int* args, int count);

int execute_func(Env* env, const char* func_name, int* args, int arg_count) {
    char path[256];
    sprintf(path, "binfuncs/%s.bin", func_name);

    size_t size;
    void* f_bin = load_binary(path, &size);

    varfunc_t f = (varfunc_t)f_bin;
    int result = f(args, arg_count);

    munmap(f_bin, size);
    return result;
}

// Simple parser: statements end with ';', assignment format var=func(args)
void run_program(const char* filename, Env* env) {
    FILE* f = fopen(filename, "r");
    if(!f) { perror("fopen"); exit(1); }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* buffer = malloc(len+1);
    fread(buffer, 1, len, f);
    buffer[len] = 0;
    fclose(f);

    char* stmt = strtok(buffer, ";");
    while(stmt) {
        while(*stmt == ' ' || *stmt=='\n') stmt++;
        if(strlen(stmt) == 0) { stmt = strtok(NULL, ";"); continue; }

        char var[128], func[128], argstr[1024];
        int n = sscanf(stmt, "%127[^=]=%127[^'('](%1023[^)])", var, func, argstr);

        // dynamic argument array
        int* args = NULL;
        int arg_count = 0;
        int arg_capacity = 0;

        if(n == 3) {
            char* token = strtok(argstr, ",");
            while(token) {
                while(*token==' ') token++;
                int value;
                if(token[0]>='0' && token[0]<='9') value = atoi(token);
                else value = env_get(env, token);

                // grow argument array
                if(arg_count >= arg_capacity) {
                    arg_capacity = arg_capacity ? arg_capacity*2 : 4;
                    args = realloc(args, arg_capacity * sizeof(int));
                    if(!args) { perror("realloc"); exit(1); }
                }
                args[arg_count++] = value;

                token = strtok(NULL, ",");
            }
        }

        int res = execute_func(env, func, args, arg_count);
        env_set(env, var, res);

        free(args);
        stmt = strtok(NULL, ";");
    }

    free(buffer);
}

int main(int argc, char** argv) {
    if(argc < 2) {
        printf("Usage: %s file.optv\n", argv[0]);
        return 1;
    }

    Env env = {0};
    run_program(argv[1], &env);

    printf("Environment:\n");
    for(int i=0; i<env.count; i++)
        printf("%s = %d\n", env.vars[i].name, env.vars[i].value);

    env_free(&env);
    return 0;
}

