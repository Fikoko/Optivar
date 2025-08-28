#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_VARS 1024
#define POOL_SIZE 1024
#define MAX_IR 8192
#define ARG_POOL_SIZE 65536

// ---------------- Types ----------------
typedef struct Var { void* data; } Var;

// ---------------- Object Pool ----------------
static Var var_pool[POOL_SIZE];
static int pool_top=0;
static Var* pool_alloc(){ return (pool_top<POOL_SIZE)?&var_pool[pool_top++]:malloc(sizeof(Var)); }
static void pool_reset(){ pool_top=0; }

// ---------------- Variable Environment ----------------
static Var* env_array[MAX_VARS];
static int var_count=0;

// ---------------- String Interning ----------------
static char* var_intern[MAX_VARS];
static int var_hash[MAX_VARS]; // simple linear probing

static int var_index(const char* name){
    for(int i=0;i<var_count;i++)
        if(var_intern[i]==name || strcmp(var_intern[i],name)==0) return i;
    Var* v=pool_alloc(); v->data=(void*)name; env_array[var_count]=v;
    var_intern[var_count]=name;
    return var_count++;
}

// ---------------- Binary Function Blob ----------------
typedef struct { char* name; void* ptr; size_t len; size_t offset; } FuncEntry;
static FuncEntry func_table[256];
static int func_count=0;
static char* func_blob=NULL;
static size_t blob_size=0;

static void preload_binfuncs(const char* dirpath){
    DIR* dir=opendir(dirpath); if(!dir){ perror("opendir"); return; }
    struct dirent* entry; size_t total_size=0;

    // Calculate total size
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type==DT_REG){
            char* name=entry->d_name; size_t len=strlen(name);
            if(len>4 && strcmp(name+len-4,".bin")==0){
                char path[256]; snprintf(path,sizeof(path),"%s/%s",dirpath,name);
                FILE* f=fopen(path,"rb"); if(!f){ perror(path); continue; }
                fseek(f,0,SEEK_END); long flen=ftell(f); fseek(f,0,SEEK_SET);
                total_size+=flen;
                fclose(f);
            }
        }
    }
    // mmap single blob
    func_blob=mmap(NULL,total_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(!func_blob){ perror("mmap blob"); return; }

    // Load functions
    size_t offset=0;
    rewinddir(dir);
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type==DT_REG){
            char* name=entry->d_name; size_t len=strlen(name);
            if(len>4 && strcmp(name+len-4,".bin")==0){
                char funcname[256]; strncpy(funcname,name,len-4); funcname[len-4]='\0';
                char path[256]; snprintf(path,sizeof(path),"%s/%s",dirpath,name);
                FILE* f=fopen(path,"rb"); if(!f){ perror(path); continue; }
                fseek(f,0,SEEK_END); long flen=ftell(f); fseek(f,0,SEEK_SET);
                fread(func_blob+offset,1,flen,f); fclose(f);

                func_table[func_count].name=strdup(funcname);
                func_table[func_count].ptr=(void*)(func_blob+offset);
                func_table[func_count].len=flen;
                func_table[func_count].offset=offset;
                offset+=flen; func_count++;
            }
        }
    }
    closedir(dir); blob_size=offset;
}

static void free_func_table(){
    for(int i=0;i<func_count;i++) free(func_table[i].name);
    if(func_blob) munmap(func_blob,blob_size);
}

// ---------------- IR ----------------
typedef struct IRStmt{ int lhs_index; void* func_ptr; int argc; int* arg_indices; } IRStmt;
typedef struct IR{ IRStmt* stmts; int count; int capacity; } IR;
static void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }
static IRStmt* ir_alloc_stmt(IR* ir){ 
    if(ir->count>=ir->capacity){ ir->capacity=ir->capacity?ir->capacity*2:8; ir->stmts=realloc(ir->stmts,sizeof(IRStmt)*ir->capacity); }
    return &ir->stmts[ir->count++];
}

// ---------------- Argument Pool ----------------
static int arg_pool[ARG_POOL_SIZE]; static int arg_top=0;
static int* arg_alloc(int n){ if(arg_top+n>ARG_POOL_SIZE){ fprintf(stderr,"Arg pool full\n"); exit(1); } int* ptr=&arg_pool[arg_top]; arg_top+=n; return ptr; }

// ---------------- Parsing ----------------
static IRStmt parse_statement(char* stmt){
    IRStmt s={0}; char* c=strstr(stmt,"--"); if(c)*c='\0';
    while(isspace(*stmt)) stmt++; if(*stmt=='\0') return s;

    char* eq=strchr(stmt,'='); if(!eq) return s; *eq='\0';
    s.lhs_index=var_index(stmt); char* rhs=eq+1; while(isspace(*rhs)) rhs++;

    char* paren=strchr(rhs,'('); if(!paren) return s; *paren='\0'; while(isspace(*rhs)) rhs++;
    // Resolve func pointer directly
    for(int i=0;i<func_count;i++) if(strcmp(func_table[i].name,rhs)==0){ s.func_ptr=func_table[i].ptr; break; }

    char* args_str=paren+1; char* close=strrchr(args_str,')'); if(!close) return s; *close='\0';
    s.arg_indices=arg_alloc(16); s.argc=0; char* p=args_str;
    while(*p){
        while(isspace(*p)) p++; if(*p==',' || *p==')'){ p++; continue; }
        char* start=p; while(*p && *p!=',' && *p!=')') p++;
        if(p>start) s.arg_indices[s.argc++]=var_index(start);
        if(*p==',') p++;
    }
    return s;
}

// ---------------- Compiler ----------------
int main(int argc,char** argv){
    if(argc<3){ printf("Usage: %s input.optivar output.oir\n",argv[0]); return 1; }

    pool_reset(); preload_binfuncs("binfuncs");

    FILE* f=fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    char* buf=malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt=strtok(buf,";");
    while(stmt){ *ir_alloc_stmt(&ir)=parse_statement(stmt); stmt=strtok(NULL,";"); }
    free(buf);

    FILE* out=fopen(argv[2],"wb"); if(!out){ perror("fopen output"); return 1; }
    fwrite(ir.stmts,sizeof(IRStmt),ir.count,out);
    fclose(out);

    pool_reset(); free_func_table();
    printf("Compilation complete: %d IR statements written to %s\n", ir.count, argv[2]);
    return 0;
}
