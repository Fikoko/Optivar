#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_IR 8192
#define FIXED_VARS 1024
#define VAR_CHUNK_SIZE 1024
#define FIXED_ARG_POOL 64
#define ARG_BLOCK_SIZE 1024
#define INLINE_THRESHOLD 3  // Inline .bin functions <=3 bytes

// ---------------- Variable Slot ----------------
typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;  
    long value;    
} VarSlot;

// ---------------- Variable Pools ----------------
static VarSlot fixed_pool[FIXED_VARS];
static int fixed_top = 0;

typedef struct VarPoolChunk {
    VarSlot* slots;
    int capacity;
    struct VarPoolChunk* next;
} VarPoolChunk;

static VarPoolChunk* dynamic_pool = NULL;

// ---------------- Environment mapping ----------------
static VarSlot** env_array = NULL;
static int var_count = 0;

// ---------------- Allocate variable slot ----------------
VarSlot* pool_alloc() {
    for (int i = 0; i < fixed_top; i++)
        if (!fixed_pool[i].in_use) { fixed_pool[i].in_use = 1; return &fixed_pool[i]; }

    if (fixed_top < FIXED_VARS) {
        VarSlot* slot = &fixed_pool[fixed_top++];
        slot->in_use = 1; slot->last_use = -1; slot->constant = 0;
        return slot;
    }

    VarPoolChunk* chunk = dynamic_pool;
    while (chunk) {
        for (int i = 0; i < chunk->capacity; i++)
            if (!chunk->slots[i].in_use) {
                chunk->slots[i].in_use = 1;
                chunk->slots[i].last_use = -1;
                chunk->slots[i].constant = 0;
                return &chunk->slots[i];
            }
        chunk = chunk->next;
    }

    VarPoolChunk* new_chunk = malloc(sizeof(VarPoolChunk));
    new_chunk->slots = calloc(VAR_CHUNK_SIZE, sizeof(VarSlot));
    new_chunk->capacity = VAR_CHUNK_SIZE;
    new_chunk->next = dynamic_pool;
    dynamic_pool = new_chunk;
    new_chunk->slots[0].in_use = 1;
    new_chunk->slots[0].last_use = -1;
    new_chunk->slots[0].constant = 0;
    return &new_chunk->slots[0];
}

// ---------------- Variable mapping ----------------
int var_index(const char* name) {
    for (int i = 0; i < var_count; i++)
        if (env_array[i]->data && strcmp((char*)env_array[i]->data, name) == 0)
            return i;

    VarSlot* slot = pool_alloc();
    slot->data = strdup(name);
    env_array = realloc(env_array, sizeof(VarSlot*) * (var_count + 1));
    env_array[var_count] = slot;
    return var_count++;
}

// ---------------- Automatic variable slot reuse ----------------
void free_vars_after(int ir_index) {
    for (int i = 0; i < fixed_top; i++)
        if (fixed_pool[i].in_use && fixed_pool[i].last_use <= ir_index)
            fixed_pool[i].in_use = 0;

    VarPoolChunk* chunk = dynamic_pool;
    while (chunk) {
        for (int i = 0; i < chunk->capacity; i++)
            if (chunk->slots[i].in_use && chunk->slots[i].last_use <= ir_index)
                chunk->slots[i].in_use = 0;
        chunk = chunk->next;
    }
}

// ---------------- Binary Function Blob ----------------
typedef struct { char* name; void* ptr; size_t len; size_t offset; } FuncEntry;
static FuncEntry func_table[256];
static int func_count = 0;
static char* func_blob = NULL;

static void preload_binfuncs(const char* dirpath) {
    DIR* dir = opendir(dirpath); if (!dir){ perror("opendir"); return; }
    struct dirent* entry; size_t total_size = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char* name = entry->d_name; size_t len = strlen(name);
            if (len > 4 && strcmp(name + len - 4, ".bin") == 0) {
                char path[256]; snprintf(path,sizeof(path),"%s/%s",dirpath,name);
                FILE* f = fopen(path,"rb"); if (!f){ perror(path); continue; }
                fseek(f,0,SEEK_END); long flen = ftell(f); fseek(f,0,SEEK_SET); total_size += flen; fclose(f);
            }
        }
    }

    func_blob = mmap(NULL,total_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (!func_blob){ perror("mmap blob"); return; }

    size_t offset = 0; rewinddir(dir);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char* name = entry->d_name; size_t len = strlen(name);
            if(len>4 && strcmp(name+len-4,".bin")==0){
                char funcname[256]; strncpy(funcname,name,len-4); funcname[len-4]='\0';
                char path[256]; snprintf(path,sizeof(path),"%s/%s",dirpath,name);
                FILE* f = fopen(path,"rb"); if(!f){ perror(path); continue; }
                fseek(f,0,SEEK_END); long flen=ftell(f); fseek(f,0,SEEK_SET);
                fread(func_blob+offset,1,flen,f); fclose(f);
                func_table[func_count].name = strdup(funcname);
                func_table[func_count].ptr = (void*)(func_blob+offset);
                func_table[func_count].len = flen;
                func_table[func_count].offset = offset;
                offset += flen; func_count++;
            }
        }
    }
    closedir(dir);
}

// ---------------- Free Function Table ----------------
static void free_func_table(){
    for(int i=0;i<func_count;i++) free(func_table[i].name);
    if(func_blob) munmap(func_blob,func_blob ? func_blob : 0);
}

// ---------------- IR ----------------
typedef struct IRStmt{
    int lhs_index;
    void* func_ptr;
    int argc;
    int* arg_indices;
    int dead;
    int inlined;
} IRStmt;

typedef struct IR{
    IRStmt* stmts;
    int count, capacity;
} IR;

void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }
IRStmt* ir_alloc_stmt(IR* ir){ 
    if(ir->count>=ir->capacity){ ir->capacity=ir->capacity?ir->capacity*2:8; ir->stmts=realloc(ir->stmts,sizeof(IRStmt)*ir->capacity); }
    return &ir->stmts[ir->count++];
}

// ---------------- Argument Pool ----------------
static int fixed_arg_pool[FIXED_ARG_POOL];
typedef struct ArgBlock { int* args; int capacity; struct ArgBlock* next; } ArgBlock;
static ArgBlock* arg_blocks = NULL;

int* arg_alloc(int n){
    if (n <= FIXED_ARG_POOL) return fixed_arg_pool;
    ArgBlock* block = arg_blocks;
    while (block) { if (block->capacity >= n) return block->args; block = block->next; }
    block = malloc(sizeof(ArgBlock));
    block->args = malloc(sizeof(int) * n);
    block->capacity = n;
    block->next = arg_blocks;
    arg_blocks = block;
    return block->args;
}

// ---------------- Parsing ----------------
static IRStmt parse_statement(char* stmt){
    IRStmt s={0}; s.dead=0;s.inlined=0;
    char* c=strstr(stmt,"--"); if(c)*c='\0';
    while(isspace(*stmt)) stmt++; if(*stmt=='\0') return s;
    char* eq=strchr(stmt,'='); if(!eq) return s; *eq='\0';
    s.lhs_index=var_index(stmt); char* rhs=eq+1; while(isspace(*rhs)) rhs++;
    char* paren=strchr(rhs,'('); if(!paren) return s; *paren='\0'; while(isspace(*rhs)) rhs++;
    for(int i=0;i<func_count;i++) if(strcmp(func_table[i].name,rhs)==0){ s.func_ptr=func_table[i].ptr; break; }
    char* args_str=paren+1; char* close=strrchr(args_str,')'); if(!close) return s; *close='\0';
    s.arg_indices=arg_alloc(16); s.argc=0; char* p=args_str;
    while(*p){ while(isspace(*p)) p++; if(*p==',' || *p==')'){ p++; continue; }
        char* start=p; while(*p && *p!=',' && *p!=')') p++;
        if(p>start) s.arg_indices[s.argc++]=var_index(start);
        if(*p==',') p++;
    }
    return s;
}

// ---------------- Optimization Passes ----------------
void constant_folding(IR* ir){
    for(int i=0;i<ir->count;i++){
        IRStmt* s = &ir->stmts[i];
        if(s->dead) continue;
        int all_const=1; long val=0;
        for(int j=0;j<s->argc;j++){
            VarSlot* arg = env_array[s->arg_indices[j]];
            if(!arg->constant){ all_const=0; break; }
            val += arg->value;
        }
        if(all_const){
            VarSlot* lhs = env_array[s->lhs_index];
            lhs->constant=1; lhs->value=val;
            s->func_ptr=NULL;
        }
    }
}

void dead_code_elimination(IR* ir){
    int used[var_count]; memset(used,0,sizeof(used));
    for(int i=ir->count-1;i>=0;i--){
        IRStmt* s = &ir->stmts[i];
        if(!s->func_ptr) continue;
        if(!used[s->lhs_index]) s->dead=1;
        for(int j=0;j<s->argc;j++) used[s->arg_indices[j]]=1;
    }
}

void ir_batching(IR* ir){
    for(int i=0;i<ir->count-1;i++){
        IRStmt* s = &ir->stmts[i];
        if(s->dead || !s->func_ptr) continue;
        IRStmt* next = &ir->stmts[i+1];
        if(next->dead || !next->func_ptr) continue;
        if(s->func_ptr == next->func_ptr){
            int total_args = s->argc + next->argc;
            int* merged_args = arg_alloc(total_args);
            memcpy(merged_args,s->arg_indices,sizeof(int)*s->argc);
            memcpy(merged_args+s->argc,next->arg_indices,sizeof(int)*next->argc);
            s->arg_indices = merged_args;
            s->argc = total_args;
            next->dead=1;
        }
    }
}

// ---------------- Runtime Execution ----------------
static void execute_stmt(IRStmt* s){
    if(s->dead) return;

    long args_values[FIXED_ARG_POOL];
    for(int i=0;i<s->argc;i++){
        VarSlot* v = env_array[s->arg_indices[i]];
        if(v->constant) args_values[i]=v->value;
        else args_values[i]=(long)v->data;
    }

    if(s->func_ptr){
        void (*fn)(long*, long*) = s->func_ptr;
        fn(&env_array[s->lhs_index]->value, args_values);
        env_array[s->lhs_index]->constant = 0;
    }
}

void execute_ir(IR* ir){
    for(int i=0;i<ir->count;i++) execute_stmt(&ir->stmts[i]);
}

// ---------------- Load IR ----------------
IR* load_oir(const char* filename){
    FILE* f = fopen(filename,"rb");
    if(!f){ perror(filename); return NULL; }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    int count = len / sizeof(IRStmt);
    IR* ir = malloc(sizeof(IR));
    ir->count = count;
    ir->stmts = malloc(sizeof(IRStmt)*count);
    fread(ir->stmts,sizeof(IRStmt),count,f);
    fclose(f);
    return ir;
}

// ---------------- Environment Init ----------------
void init_env(int total_vars){
    env_array = malloc(sizeof(VarSlot*)*total_vars);
    for(int i=0;i<total_vars;i++){
        env_array[i] = malloc(sizeof(VarSlot));
        env_array[i]->data=NULL;
        env_array[i]->constant=0;
        env_array[i]->value=0;
    }
    var_count = total_vars;
}

void free_env(){
    for(int i=0;i<var_count;i++) free(env_array[i]);
    free(env_array);
}

// ---------------- Compiler + Runtime Main ----------------
int main(int argc,char** argv){
    if(argc<3){ printf("Usage: %s input.optivar binfuncs_dir\n",argv[0]); return 1; }

    preload_binfuncs(argv[2]);

    FILE* f=fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    char* buf=malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt=strtok(buf,";");
    int stmt_index=0;
    while(stmt){
        IRStmt s = parse_statement(stmt);
        for(int i=0;i<s.argc;i++){
            VarSlot* slot = env_array[s.arg_indices[i]];
            if(slot->last_use < stmt_index) slot->last_use = stmt_index;
        }
        IRStmt* ir_stmt = ir_alloc_stmt(&ir);
        *ir_stmt = s;
        stmt=strtok(NULL,";");
        stmt_index++;
    }
    free(buf);

    // Optimization passes
    constant_folding(&ir);
    dead_code_elimination(&ir);
    ir_batching(&ir);

    // Execute IR immediately
    int max_var_index=0;
    for(int i=0;i<ir.count;i++)
        if(ir.stmts[i].lhs_index>max_var_index) max_var_index=ir.stmts[i].lhs_index;
    init_env(max_var_index+1);

    execute_ir(&ir);

    for(int i=0;i<var_count;i++)
        printf("Var %d = %ld\n", i, env_array[i]->value);

    free_env();
    free_func_table();
    free(ir.stmts);

    return 0;
}
