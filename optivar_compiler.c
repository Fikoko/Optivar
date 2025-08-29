#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_IR 8192
#define FIXED_VARS 1024
#define VAR_CHUNK_SIZE 1024
#define FIXED_ARG_POOL 64
#define INLINE_THRESHOLD 3
#define MAX_NAME_LEN 128

typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    pthread_mutex_t lock;
} VarSlot;

static VarSlot fixed_pool[FIXED_VARS];
static int fixed_top = 0;

typedef struct VarPoolChunk { 
    VarSlot* slots; 
    int capacity; 
    struct VarPoolChunk* next; 
} VarPoolChunk;
static VarPoolChunk* dynamic_pool = NULL;

static VarSlot** env_array = NULL;
static int var_count = 0;
static int env_alloc_size = 0;

#define VAR_TABLE_SIZE 2048
static VarSlot* var_table[VAR_TABLE_SIZE];

unsigned int hash_name(const char* s) {
    unsigned int h = 0;
    while(*s) h = (h * 31) + (*s++);
    return h % VAR_TABLE_SIZE;
}

VarSlot* pool_alloc() {
    for(int i=0;i<fixed_top;i++) 
        if(!fixed_pool[i].in_use){ 
            fixed_pool[i].in_use=1; 
            return &fixed_pool[i];
        }
    if(fixed_top<FIXED_VARS){ 
        VarSlot* slot=&fixed_pool[fixed_top++]; 
        slot->in_use=1; slot->last_use=-1; slot->constant=0; 
        return slot; 
    }
    VarPoolChunk* chunk=dynamic_pool;
    while(chunk){ 
        for(int i=0;i<chunk->capacity;i++) 
            if(!chunk->slots[i].in_use){ 
                chunk->slots[i].in_use=1; 
                chunk->slots[i].last_use=-1; 
                chunk->slots[i].constant=0; 
                return &chunk->slots[i]; 
            } 
        chunk=chunk->next;
    }
    VarPoolChunk* new_chunk=malloc(sizeof(VarPoolChunk));
    new_chunk->slots=calloc(VAR_CHUNK_SIZE,sizeof(VarSlot));
    new_chunk->capacity=VAR_CHUNK_SIZE;
    new_chunk->next=dynamic_pool;
    dynamic_pool=new_chunk;
    new_chunk->slots[0].in_use=1; 
    new_chunk->slots[0].last_use=-1; 
    new_chunk->slots[0].constant=0;
    return &new_chunk->slots[0];
}

int var_index(const char* name) {
    unsigned int h=hash_name(name);
    for(int i=0;i<VAR_TABLE_SIZE;i++){
        unsigned int idx=(h+i)%VAR_TABLE_SIZE;
        if(!var_table[idx]){
            VarSlot* slot=pool_alloc(); 
            slot->data=strdup(name); 
            var_table[idx]=slot;
            if(var_count >= env_alloc_size){
                env_alloc_size *= 2;
                env_array = realloc(env_array, sizeof(VarSlot*) * env_alloc_size);
            }
            env_array[var_count]=slot; 
            return var_count++;
        }
        if(strcmp((char*)var_table[idx]->data,name)==0){ 
            for(int j=0;j<var_count;j++) 
                if(env_array[j]==var_table[idx]) return j;
        }
    }
    return -1;
}

void free_vars_after(int ir_index) {
    for(int i=0;i<fixed_top;i++) 
        if(fixed_pool[i].in_use && fixed_pool[i].last_use<=ir_index) 
            fixed_pool[i].in_use=0;
    VarPoolChunk* chunk=dynamic_pool;
    while(chunk){ 
        for(int i=0;i<chunk->capacity;i++) 
            if(chunk->slots[i].in_use && chunk->slots[i].last_use<=ir_index) 
                chunk->slots[i].in_use=0;
        chunk=chunk->next; 
    }
}

typedef struct { 
    char name[MAX_NAME_LEN]; 
    void* ptr; 
    size_t len; 
    size_t offset; 
} FuncEntry;

static FuncEntry func_table[256]; 
static int func_count=0;
static char* func_blob=NULL; 
static size_t func_blob_size=0;

void preload_binfuncs(const char* dirpath) {
    DIR* dir=opendir(dirpath); if(!dir){ perror("opendir"); return; }
    struct dirent* entry; size_t total_size=0;
    while((entry=readdir(dir))!=NULL){ 
        if(entry->d_type!=DT_REG) continue; 
        size_t len=strlen(entry->d_name); 
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){ 
            struct stat st; char path[256]; 
            snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name); 
            if(stat(path,&st)==0) total_size+=st.st_size; 
        } 
    }
    closedir(dir); 
    if(total_size==0) return;
    func_blob=mmap(NULL,total_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(!func_blob){ perror("mmap"); return; } 
    func_blob_size=total_size;
    dir=opendir(dirpath); if(!dir){ perror("opendir"); return; }
    size_t offset=0;
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type!=DT_REG) continue; 
        size_t len=strlen(entry->d_name); 
        if(len>4 && strcmp(entry->d_name+len-4,".bin")==0){
            char funcname[MAX_NAME_LEN]; 
            strncpy(funcname,entry->d_name,len-4); 
            funcname[len-4]='\0';
            char path[256]; 
            snprintf(path,sizeof(path),"%s/%s",dirpath,entry->d_name);
            FILE* f=fopen(path,"rb"); 
            if(!f){ perror(path); continue; }
            fseek(f,0,SEEK_END); 
            long flen=ftell(f); 
            fseek(f,0,SEEK_SET);
            fread(func_blob+offset,1,flen,f); 
            fclose(f);
            strncpy(func_table[func_count].name,funcname,MAX_NAME_LEN); 
            func_table[func_count].ptr=(void*)(func_blob+offset); 
            func_table[func_count].len=flen; 
            func_table[func_count].offset=offset; 
            offset+=flen; 
            func_count++;
        }
    }
    closedir(dir);
}

void free_func_table(){ if(func_blob) munmap(func_blob,func_blob_size); }

typedef struct IRStmt{
    int lhs_index;
    void* func_ptr;
    int argc;
    int* arg_indices;
    int dead;
    int inlined;
    int dep_count;
    int* dep_indices;
    int executed;
} IRStmt;

typedef struct IR{ IRStmt* stmts; int count, capacity; } IR;

void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }
IRStmt* ir_alloc_stmt(IR* ir){ 
    if(ir->count>=ir->capacity){ 
        ir->capacity=ir->capacity?ir->capacity*2:8; 
        ir->stmts=realloc(ir->stmts,sizeof(IRStmt)*ir->capacity); 
    } 
    return &ir->stmts[ir->count++]; 
}

typedef struct ArgBlock{ int* args; int capacity; int used; struct ArgBlock* next; } ArgBlock;
static ArgBlock* arg_blocks=NULL;

int* arg_alloc(int n){
    ArgBlock* block=arg_blocks;
    while(block){
        if(block->capacity - block->used >= n){
            int* ptr = block->args + block->used;
            block->used += n;
            return ptr;
        }
        block = block->next;
    }
    block = malloc(sizeof(ArgBlock));
    block->capacity = n>FIXED_ARG_POOL ? n : FIXED_ARG_POOL;
    block->args = malloc(sizeof(int) * block->capacity);
    block->used = n;
    block->next = arg_blocks;
    arg_blocks = block;
    return block->args;
}

void free_arg_blocks(){ 
    ArgBlock* block=arg_blocks; 
    while(block){ 
        ArgBlock* next=block->next; 
        free(block->args); free(block); 
        block=next; 
    } 
    arg_blocks=NULL; 
}

IRStmt parse_statement(char* stmt){
    IRStmt s={0}; s.dead=0; s.inlined=0;
    char* c=strstr(stmt,"--"); if(c)*c='\0';
    while(isspace(*stmt)) stmt++; if(*stmt=='\0') return s;
    char* eq=strchr(stmt,'='); if(!eq) return s; *eq='\0';
    s.lhs_index=var_index(stmt); 
    char* rhs=eq+1; while(isspace(*rhs)) rhs++;
    char* paren=strchr(rhs,'('); if(!paren) return s; *paren='\0'; while(isspace(*rhs)) rhs++;
    for(int i=0;i<func_count;i++) 
        if(strcmp(func_table[i].name,rhs)==0){ 
            s.func_ptr=func_table[i].ptr; 
            if(func_table[i].len<=INLINE_THRESHOLD) s.inlined=1; 
            break; 
        }
    char* args_str=paren+1; 
    char* close=strrchr(args_str,')'); if(!close) return s; *close='\0';
    int arg_cap=16; 
    s.arg_indices=arg_alloc(arg_cap); s.argc=0; 
    char* p=args_str;
    while(*p){
        while(isspace(*p)) p++; 
        if(*p==',' || *p==')'){ p++; continue; } 
        char* start=p; 
        while(*p && *p!=',' && *p!=')') p++; 
        if(p>start){ 
            if(s.argc>=arg_cap){ 
                arg_cap*=2; 
                int* new_args=arg_alloc(arg_cap); 
                memcpy(new_args,s.arg_indices,sizeof(int)*s.argc); 
                s.arg_indices=new_args; 
            } 
            s.arg_indices[s.argc++]=var_index(start); 
        } 
        if(*p==',') p++; 
    }
    return s;
}

void constant_folding(IR* ir){ 
    for(int i=0;i<ir->count;i++){ 
        IRStmt* s=&ir->stmts[i]; if(s->dead) continue; 
        int all_const=1; long val=0; 
        for(int j=0;j<s->argc;j++){ 
            VarSlot* arg=env_array[s->arg_indices[j]]; 
            if(!arg->constant){ all_const=0; break; } 
            val+=arg->value; 
        } 
        if(all_const){ 
            VarSlot* lhs=env_array[s->lhs_index]; 
            lhs->constant=1; lhs->value=val; s->func_ptr=NULL; 
        } 
    } 
}

void dead_code_elimination(IR* ir){ 
    int used[var_count]; memset(used,0,sizeof(used)); 
    for(int i=ir->count-1;i>=0;i--){ 
        IRStmt* s=&ir->stmts[i]; 
        if(!s->func_ptr) continue; 
        if(!used[s->lhs_index]) s->dead=1; 
        for(int j=0;j<s->argc;j++) used[s->arg_indices[j]]=1; 
    } 
}

void ir_batching(IR* ir){ 
    for(int i=0;i<ir->count-1;i++){ 
        IRStmt* s=&ir->stmts[i]; 
        if(s->dead||!s->func_ptr) continue; 
        IRStmt* next=&ir->stmts[i+1]; 
        if(next->dead||!next->func_ptr) continue; 
        if(s->func_ptr==next->func_ptr){ 
            int total_args=s->argc+next->argc; 
            int* merged=arg_alloc(total_args); 
            memcpy(merged,s->arg_indices,sizeof(int)*s->argc); 
            memcpy(merged+s->argc,next->arg_indices,sizeof(int)*next->argc); 
            s->arg_indices=merged; 
            s->argc=total_args; 
            next->dead=1; 
        } 
    } 
}

void build_dependencies(IR* ir){ 
    for(int i=0;i<ir->count;i++){ 
        IRStmt* s=&ir->stmts[i]; s->dep_count=0; s->dep_indices=NULL; s->executed=0; 
        for(int j=0;j<i;j++){ 
            IRStmt* prev=&ir->stmts[j]; 
            for(int k=0;k<s->argc;k++){ 
                if(prev->lhs_index==s->arg_indices[k]){ 
                    s->dep_count++; 
                    s->dep_indices=realloc(s->dep_indices,sizeof(int)*s->dep_count); 
                    s->dep_indices[s->dep_count-1]=j; 
                    break; 
                } 
            } 
        } 
    } 
}

void init_env(int total_vars){ 
    env_array=malloc(sizeof(VarSlot*)*total_vars); 
    env_alloc_size=total_vars; 
    for(int i=0;i<total_vars;i++){ 
        env_array[i]=malloc(sizeof(VarSlot)); 
        env_array[i]->data=NULL; 
        env_array[i]->constant=0; 
        env_array[i]->value=0; 
        pthread_mutex_init(&env_array[i]->lock,NULL);
    } 
    var_count=0; 
}

void free_env(){ 
    for(int i=0;i<var_count;i++){ 
        if(env_array[i]->data) free(env_array[i]->data); 
        pthread_mutex_destroy(&env_array[i]->lock);
        free(env_array[i]); 
    } 
    free(env_array); 
}

int main(int argc,char** argv){
    if(argc<3){ printf("Usage: %s input.optivar binfuncs_dir\n",argv[0]); return 1; }
    init_env(FIXED_VARS*2);
    preload_binfuncs(argv[2]);
    FILE* f=fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    char* buf=malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';
    IR ir; ir_init(&ir); char* stmt=strtok(buf,";"); int stmt_index=0;
    while(stmt){
        IRStmt s=parse_statement(stmt);
        for(int i=0;i<s.argc;i++){ 
            VarSlot* slot=env_array[s.arg_indices[i]]; 
            if(slot->last_use<stmt_index) slot->last_use=stmt_index; 
        }
        IRStmt* ir_stmt=ir_alloc_stmt(&ir); *ir_stmt=s; stmt=strtok(NULL,";"); stmt_index++;
    }
    free(buf);
    constant_folding(&ir); dead_code_elimination(&ir); ir_batching(&ir);
    build_dependencies(&ir);

    // Call .bin executor
    if(func_count>0 && func_table[0].ptr) { 
        void (*bin_exec)(IRStmt*, int, VarSlot**, int) = func_table[0].ptr; 
        bin_exec(ir.stmts, ir.count, env_array, 8); 
    }

    for(int i=0;i<var_count;i++) printf("Var %d = %ld\n",i,env_array[i]->value);
    free_env(); free_func_table(); free(ir.stmts); free_arg_blocks();
    return 0;
}
