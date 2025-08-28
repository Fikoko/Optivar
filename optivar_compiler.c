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
#define FUNC_HASH_SIZE 256

// ---------------- Types ----------------
typedef struct Var {
    void* data;
} Var;

// ---------------- Object Pool ----------------
typedef struct {
    Var pool[POOL_SIZE];
    int top;
} VarPool;

static VarPool var_pool;
static void pool_init() { var_pool.top = 0; }
static Var* pool_alloc() { 
    if(var_pool.top<POOL_SIZE) return &var_pool.pool[var_pool.top++];
    return malloc(sizeof(Var));
}
static void pool_reset() { var_pool.top=0; } // reset once at program end

// ---------------- Environment ----------------
static Var* env_array[MAX_VARS];
static int var_count = 0;

// ---------------- Variable Hash ----------------
typedef struct VarEntry {
    char* name;
    int index;
    struct VarEntry* next;
} VarEntry;

static VarEntry* var_hash[MAX_VARS*2];

static unsigned int hash_string(const char* s){
    unsigned int h=5381;
    while(*s) h=((h<<5)+h)+(unsigned char)(*s++);
    return h%(MAX_VARS*2);
}

static int var_index(const char* name){
    unsigned int h=hash_string(name);
    VarEntry* e=var_hash[h];
    while(e){ if(strcmp(e->name,name)==0) return e->index; e=e->next; }
    if(var_count>=MAX_VARS){ fprintf(stderr,"Too many variables\n"); exit(1); }
    Var* v=pool_alloc(); v->data=strdup(name); env_array[var_count]=v;

    VarEntry* ne=malloc(sizeof(VarEntry));
    ne->name=(char*)v->data; ne->index=var_count; ne->next=var_hash[h];
    var_hash[h]=ne;

    return var_count++;
}

// ---------------- Binary Function Cache ----------------
typedef Var* (*varfunc_t)(Var** args,int argc);

typedef struct FuncEntry {
    char* name;
    varfunc_t func;
    void* buf;
    size_t len;
    struct FuncEntry* next;
} FuncEntry;

static FuncEntry* func_hash[FUNC_HASH_SIZE];

static unsigned int hash_funcname(const char* s){
    unsigned int h=5381; while(*s) h=((h<<5)+h)+(unsigned char)(*s++);
    return h%FUNC_HASH_SIZE;
}

static void insert_func(FuncEntry* f){
    unsigned int h=hash_funcname(f->name); f->next=func_hash[h]; func_hash[h]=f;
}

static varfunc_t get_func(const char* name){
    unsigned int h=hash_funcname(name); FuncEntry* e=func_hash[h];
    while(e){ if(strcmp(e->name,name)==0) return e->func; e=e->next; }
    return NULL;
}

static void preload_binfuncs(const char* dirpath){
    DIR* dir=opendir(dirpath);
    if(!dir){ perror("opendir"); return; }
    struct dirent* entry;
    while((entry=readdir(dir))!=NULL){
        if(entry->d_type==DT_REG){
            char* name=entry->d_name; size_t len=strlen(name);
            if(len>4 && strcmp(name+len-4,".bin")==0){
                char funcname[256]; strncpy(funcname,name,len-4); funcname[len-4]='\0';
                char path[256]; snprintf(path,sizeof(path),"%s/%s.bin",dirpath,funcname);
                FILE* f=fopen(path,"rb"); if(!f){ perror(path); continue; }
                fseek(f,0,SEEK_END); long flen=ftell(f); fseek(f,0,SEEK_SET);
                void* buf=mmap(NULL,flen,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
                if(!buf){ fclose(f); perror("mmap"); continue; }
                if(fread(buf,1,flen,f)!=flen){ fclose(f); munmap(buf,flen); continue; }
                fclose(f);

                FuncEntry* fe=malloc(sizeof(FuncEntry));
                fe->name=strdup(funcname); fe->func=(varfunc_t)buf;
                fe->buf=buf; fe->len=flen; fe->next=NULL;
                insert_func(fe);
            }
        }
    }
    closedir(dir);
}

static void free_func_table(){
    for(int i=0;i<FUNC_HASH_SIZE;i++){
        FuncEntry* e=func_hash[i];
        while(e){ FuncEntry* tmp=e; e=e->next; free(tmp->name); if(tmp->buf&&tmp->len>0) munmap(tmp->buf,tmp->len); free(tmp); }
        func_hash[i]=NULL;
    }
}

// ---------------- IR ----------------
typedef struct IRStmt{
    int lhs_index;
    varfunc_t func_ptr;
    int* arg_indices;
    int argc;
} IRStmt;

typedef struct IR{
    IRStmt* stmts;
    int count;
    int capacity;
} IR;

static void ir_init(IR* ir){ ir->stmts=NULL; ir->count=ir->capacity=0; }
static void ir_add(IR* ir,IRStmt s){ 
    if(ir->count>=ir->capacity){ ir->capacity=ir->capacity?ir->capacity*2:8; ir->stmts=realloc(ir->stmts,sizeof(IRStmt)*ir->capacity); }
    ir->stmts[ir->count++]=s;
}
static void ir_free(IR* ir){ for(int i=0;i<ir->count;i++) free(ir->stmts[i].arg_indices); free(ir->stmts); }

// ---------------- Parsing ----------------
static IRStmt parse_statement(char* stmt){
    IRStmt s={0};
    char* comment=strstr(stmt,"--"); if(comment)*comment='\0';
    while(isspace(*stmt)) stmt++;
    if(*stmt=='\0') return s;

    char* eq=strchr(stmt,'='); if(!eq) return s; *eq='\0';
    s.lhs_index=var_index(stmt);
    char* rhs=eq+1; while(isspace(*rhs)) rhs++;
    char* paren=strchr(rhs,'('); if(!paren) return s; *paren='\0';

    char funcname[256]; strcpy(funcname,rhs); while(isspace(*funcname)) funcname++;
    s.func_ptr=get_func(funcname);

    char* args_str=paren+1;
    char* close=strrchr(args_str,')'); if(!close) return s; *close='\0';

    int cap=4; s.arg_indices=malloc(sizeof(int)*cap); s.argc=0;
    char* token=strtok(args_str,",");
    while(token){
        while(isspace(*token)) token++;
        if(*token=='\0'){ token=strtok(NULL,","); continue; }
        if(s.argc>=cap){ cap*=2; s.arg_indices=realloc(s.arg_indices,sizeof(int)*cap); }
        s.arg_indices[s.argc++]=var_index(token);
        token=strtok(NULL,",");
    }
    return s;
}

// ---------------- Compiler ----------------
int main(int argc,char** argv){
    if(argc<3){ printf("Usage: %s input.optivar output.oir\n",argv[0]); return 1; }

    pool_init();
    preload_binfuncs("binfuncs");

    FILE* f=fopen(argv[1],"r"); if(!f){ perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    char* buf=malloc(len+1); fread(buf,1,len,f); fclose(f); buf[len]='\0';

    IR ir; ir_init(&ir);
    char* stmt=strtok(buf,";");
    while(stmt){ ir_add(&ir,parse_statement(stmt)); stmt=strtok(NULL,";"); }
    free(buf);

    FILE* out=fopen(argv[2],"wb");
    if(!out){ perror("fopen output"); return 1; }
    fwrite(ir.stmts,sizeof(IRStmt),ir.count,out);
    fclose(out);

    pool_reset();
    ir_free(&ir);
    free_func_table();

    printf("Compilation complete: %d IR statements written to %s\n", ir.count, argv[2]);
    return 0;
}
