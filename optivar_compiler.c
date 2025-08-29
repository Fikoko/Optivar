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

// ---------------- Variable Slot ----------------
typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
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
    // Try to reuse fixed pool
    for (int i = 0; i < fixed_top; i++)
        if (!fixed_pool[i].in_use) { fixed_pool[i].in_use = 1; return &fixed_pool[i]; }

    if (fixed_top < FIXED_VARS) {
        VarSlot* slot = &fixed_pool[fixed_top++];
        slot->in_use = 1; slot->last_use = -1; return slot;
    }

    // Try to reuse dynamic pool slots
    VarPoolChunk* chunk = dynamic_pool;
    while (chunk) {
        for (int i = 0; i < chunk->capacity; i++)
            if (!chunk->slots[i].in_use) { chunk->slots[i].in_use = 1; chunk->slots[i].last_use = -1; return &chunk->slots[i]; }
        chunk = chunk->next;
    }

    // Allocate new dynamic chunk
    VarPoolChunk* new_chunk = malloc(sizeof(VarPoolChunk));
    new_chunk->slots = calloc(VAR_CHUNK_SIZE, sizeof(VarSlot));
    new_chunk->capacity = VAR_CHUNK_SIZE;
    new_chunk->next = dynamic_pool;
    dynamic_pool = new_chunk;
    new_chunk->slots[0].in_use = 1;
    new_chunk->slots[0].last_use = -1;
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
static size_t blob_size = 0;

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
    closedir(dir); blob_size = offset;
}

static void free_func_table(){
    for(int i=0;i<func_count;i++) free(func_table[i].name);
    if(func_blob) munmap(func_blob,blob_size);
}

// ---------------- IR ----------------
typedef struct IRStmt{
    int lhs_index;
    void* func_ptr;
    int argc;
    int* arg_indices;
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

// ---------------- Argument Pool (Unlimited) ----------------
static int fixed_arg_pool[FIXED_ARG_POOL];
typedef struct ArgBlock { int* args; int capacity; struct ArgBlock* next; } ArgBlock;
static ArgBlock* arg_blocks = NULL;

int* arg_alloc(int n){
    if (n <= FIXED_ARG_POOL) return fixed_arg_pool;  // fast path
    ArgBlock* block = arg_blocks;
    while (block) {
        if (block->capacity >= n) { return block->args; }
        block = block->next;
    }
    block = malloc(sizeof(ArgBlock));
    block->args = malloc(sizeof(int) * n);
    block->capacity = n;
    block->next = arg_blocks;
    arg_blocks = block;
    return block->args;
}

// ---------------- Parsing ----------------
static IRStmt parse_statement(char* stmt){
    IRStmt s={0}; char* c=strstr(stmt,"--"); if(c)*c='\0';
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

// ---------------- Compiler ----------------
int main(int argc,char** argv){
    if(argc<3){ printf("Usage: %s input.optivar output.oir\n",argv[0]); return 1; }

    preload_binfuncs("binfuncs");

    FILE* f=fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    char* buf=malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt=strtok(buf,";");
    int stmt_index=0;
    while(stmt){
        IRStmt s = parse_statement(stmt);

        // Update last use for arguments
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

    FILE* out=fopen(argv[2],"wb"); if(!out){ perror("fopen output"); return 1; }
    fwrite(ir.stmts,sizeof(IRStmt),ir.count,out);
    fclose(out);

    free_func_table();
    printf("Compilation complete: %d IR statements written to %s\n", ir.count, argv[2]);
    return 0;
}
