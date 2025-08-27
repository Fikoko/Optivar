/* universal_debugger.c
 *
 * Universal interactive debugger for Optivar orchestrator:
 *  - parses .optivar files
 *  - manages variables generically
 *  - reuses memory slots instead of freeing
 *  - prompts user when a variable reaches last use
 *  - writes optimized .optivar with slot assignments
 *
 * Compile:
 *   gcc -std=c11 -O2 -o universal_debugger universal_debugger.c
 *
 * Usage:
 *   ./universal_debugger src.optivar dst.optivar
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* ---------------- Utilities ---------------- */

static char *strdup_safe(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (!d) { perror("malloc"); exit(1); }
    memcpy(d, s, n);
    return d;
}

static void trim_inplace(char *s) {
    if (!s) return;
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    int n = (int)strlen(s);
    while (n > 0 && isspace((unsigned char)s[n-1])) s[--n] = '\0';
}

/* ---------------- Data Structures ---------------- */

typedef struct {
    char *name;
    int slot;             // -1 if not assigned
    int total_uses;
    int remaining_uses;
    int line_decl;
} Var;

typedef struct {
    char *func_name;
    char *lhs;
    char **args;
    int arg_count;
    int line_no;
} Stmt;

typedef struct {
    Var **items;
    int count;
    int cap;
} VarList;

typedef struct {
    Stmt **items;
    int count;
    int cap;
} StmtList;

typedef struct {
    char **slots;    // slot index -> variable name
    int capacity;
    int *used;
    int *free_stack;
    int free_top;
} SlotState;

/* ---------------- VarList Utilities ---------------- */

static void varlist_init(VarList *vl) { vl->items = NULL; vl->count = 0; vl->cap = 0; }
static void stmtlist_init(StmtList *sl) { sl->items = NULL; sl->count = 0; sl->cap = 0; }

static Var *varlist_find(VarList *vl, const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < vl->count; i++)
        if (strcmp(vl->items[i]->name, name) == 0) return vl->items[i];
    return NULL;
}

static Var *varlist_add(VarList *vl, const char *name, int line_no) {
    Var *v = varlist_find(vl, name);
    if (v) return v;
    if (vl->count >= vl->cap) {
        vl->cap = vl->cap ? vl->cap * 2 : 32;
        vl->items = realloc(vl->items, sizeof(Var*) * vl->cap);
        if (!vl->items) { perror("realloc"); exit(1); }
    }
    v = malloc(sizeof(Var));
    v->name = strdup_safe(name);
    v->slot = -1;
    v->total_uses = 0;
    v->remaining_uses = 0;
    v->line_decl = line_no;
    vl->items[vl->count++] = v;
    return v;
}

static void stmtlist_add(StmtList *sl, Stmt *s) {
    if (sl->count >= sl->cap) {
        sl->cap = sl->cap ? sl->cap * 2 : 32;
        sl->items = realloc(sl->items, sizeof(Stmt*) * sl->cap);
        if (!sl->items) { perror("realloc"); exit(1); }
    }
    sl->items[sl->count++] = s;
}

/* ---------------- File Parsing ---------------- */

static char *read_file_all(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) { perror("malloc"); fclose(f); return NULL; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    return buf;
}

static void strip_comments(char *s) {
    char *p = s;
    while (*p) {
        if (p[0]=='-' && p[1]=='-') {
            char *q = p;
            while (*q && *q != '\n') q++;
            memmove(p, q, strlen(q)+1);
            continue;
        }
        p++;
    }
}

static Stmt *parse_statement(char *txt, int line_no) {
    char *eq = strchr(txt, '=');
    if (!eq) return NULL;
    *eq = '\0';
    char *lhs = strdup_safe(txt); trim_inplace(lhs);
    char *rhs = strdup_safe(eq+1); trim_inplace(rhs);
    int rl = (int)strlen(rhs); if(rl>0 && rhs[rl-1]==';') rhs[rl-1]='\0';
    char *paren = strchr(rhs,'(');
    if(!paren) { free(lhs); free(rhs); return NULL; }
    *paren='\0';
    char *fname = strdup_safe(rhs); trim_inplace(fname);
    char *args_area = strdup_safe(paren+1);
    char *rc = strrchr(args_area,')'); if(rc)*rc='\0'; trim_inplace(args_area);

    Stmt *s = malloc(sizeof(Stmt));
    s->func_name = strdup_safe(fname);
    s->lhs = strdup_safe(lhs);
    s->line_no = line_no;
    s->arg_count=0; s->args=NULL;

    if(strlen(args_area)>0){
        char *save=NULL; char *tok=strtok_r(args_area,",",&save);
        while(tok){
            trim_inplace(tok);
            if(strlen(tok)){
                s->args = realloc(s->args,sizeof(char*)*(s->arg_count+1));
                s->args[s->arg_count++] = strdup_safe(tok);
            }
            tok=strtok_r(NULL,",",&save);
        }
    }
    free(lhs); free(rhs); free(fname); free(args_area);
    return s;
}

static int parse_program(const char *path, StmtList *out_stmts, VarList *out_vars){
    char *all = read_file_all(path);
    if(!all) return -1;
    strip_comments(all);
    char *p=all, *start=p;
    int line_no=1;
    for(;*p;p++){
        if(*p=='\n') line_no++;
        if(*p==';'){
            size_t len=p-start+1;
            char *chunk=malloc(len+1); memcpy(chunk,start,len); chunk[len]='\0';
            char *work=strdup_safe(chunk); trim_inplace(work);
            if(strlen(work)>0){
                Stmt *s=parse_statement(work,line_no);
                if(s){
                    stmtlist_add(out_stmts,s);
                    varlist_add(out_vars,s->lhs,s->line_no);
                    for(int i=0;i<s->arg_count;i++) varlist_add(out_vars,s->args[i],s->line_no);
                }
            }
            free(chunk); free(work); start=p+1;
        }
    }
    free(all); return 0;
}

/* ---------------- Usage Counts ---------------- */

static void compute_usage_counts(StmtList *stmts, VarList *vars){
    for(int i=0;i<vars->count;i++) vars->items[i]->total_uses=vars->items[i]->remaining_uses=0;
    for(int si=0;si<stmts->count;si++){
        Stmt *s=stmts->items[si];
        for(int a=0;a<s->arg_count;a++){
            Var *v=varlist_find(vars,s->args[a]);
            if(v) v->total_uses++;
        }
    }
    for(int i=0;i<vars->count;i++) vars->items[i]->remaining_uses=vars->items[i]->total_uses;
}

/* ---------------- Slot Management ---------------- */

static void slotstate_init(SlotState *ss){ ss->slots=NULL; ss->capacity=0; ss->used=NULL; ss->free_stack=NULL; ss->free_top=0; }

static void slotstate_ensure(SlotState *ss,int need){
    if(ss->capacity>=need) return;
    int newc=ss->capacity?ss->capacity*2:8; while(newc<need) newc*=2;
    ss->slots=realloc(ss->slots,sizeof(char*)*newc);
    ss->used=realloc(ss->used,sizeof(int)*newc);
    for(int i=ss->capacity;i<newc;i++){ss->slots[i]=NULL; ss->used[i]=0;}
    ss->capacity=newc;
}

static int slot_pop_free(SlotState *ss){ return ss->free_top==0?-1:ss->free_stack[--ss->free_top]; }
static void slot_push_free(SlotState *ss,int idx){ ss->free_stack=realloc(ss->free_stack,sizeof(int)*(ss->free_top+1)); ss->free_stack[ss->free_top++]=idx; }
static int allocate_slot(SlotState *ss,const char *varname){
    int idx=slot_pop_free(ss); if(idx>=0){ if(ss->slots[idx]) free(ss->slots[idx]); ss->slots[idx]=strdup_safe(varname); ss->used[idx]=1; return idx; }
    for(int i=0;i<ss->capacity;i++){ if(!ss->used[i]){ if(ss->slots[i]) free(ss->slots[i]); ss->slots[i]=strdup_safe(varname); ss->used[i]=1; return i; } }
    int old=ss->capacity; slotstate_ensure(ss,old+1); ss->slots[old]=strdup_safe(varname); ss->used[old]=1; return old;
}
static void free_slot(SlotState *ss,int idx){ if(idx<0||idx>=ss->capacity||!ss->used[idx]) return; ss->used[idx]=0; slot_push_free(ss,idx); }

/* ---------------- Interactive Last-use Prompt ---------------- */

static int prompt_keep_var(const char *varname,int line_no){
    char buf[8];
    printf("Line %d: variable '%s' is dead. Keep it? (y/n): ",line_no,varname);
    if(!fgets(buf,sizeof(buf),stdin)) return 0;
    char c='n'; for(int i=0;buf[i];i++){ if(!isspace((unsigned char)buf[i])){ c=buf[i]; break; } }
    return (c=='y'||c=='Y');
}

/* ---------------- Optimize & Write ---------------- */

static void optimize_and_write_interactive(const char *dst,StmtList *stmts,VarList *vars){
    SlotState ss; slotstate_init(&ss);
    FILE *fout=fopen(dst,"wb"); if(!fout){perror("fopen"); return;}
    for(int i=0;i<stmts->count;i++){
        Stmt *s=stmts->items[i];
        Var *lhs=varlist_find(vars,s->lhs); if(!lhs) lhs=varlist_add(vars,s->lhs,s->line_no);
        int reuse=-1;
        for(int a=0;a<s->arg_count;a++){
            Var *v=varlist_find(vars,s->args[a]);
            if(v && v->remaining_uses==1 && v->slot!=-1){ reuse=v->slot; break; }
        }
        if(reuse!=-1){ lhs->slot=reuse; if(ss.slots[reuse]) free(ss.slots[reuse]); ss.slots[reuse]=strdup_safe(lhs->name);}
        else lhs->slot=allocate_slot(&ss,lhs->name);

        // write statement
        fprintf(fout,"slot%d = %s(",lhs->slot,s->func_name);
        for(int a=0;a<s->arg_count;a++){
            Var *v=varlist_find(vars,s->args[a]);
            if(a) fprintf(fout,", ");
            fprintf(fout,"slot%d",v?v->slot:-1);
            if(v && v->remaining_uses>0) v->remaining_uses--;
            if(v && v->remaining_uses==0){
                int keep=prompt_keep_var(v->name,s->line_no);
                if(!keep){ free_slot(&ss,v->slot); v->slot=-1; }
            }
        }
        fprintf(fout,"); // %s = %s\n",s->lhs,s->func_name);
    }
    fclose(fout);
    for(int i=0;i<ss.capacity;i++) if(ss.slots[i]) free(ss.slots[i]);
    free(ss.slots); free(ss.used); free(ss.free_stack);
}

/* ---------------- Cleanup ---------------- */

static void free_program(StmtList *sl,VarList *vl){
    for(int i=0;i<sl->count;i++){
        Stmt *s=sl->items[i]; free(s->lhs); free(s->func_name);
        for(int j=0;j<s->arg_count;j++) free(s->args[j]);
        free(s->args); free(s);
    }
    free(sl->items);
    for(int i=0;i<vl->count;i++){ free(vl->items[i]->name); free(vl->items[i]); }
    free(vl->items);
}

/* ---------------- Main ---------------- */

int main(int argc,char **argv){
    if(argc<3){ fprintf(stderr,"Usage: %s src.optivar dst.optivar\n",argv[0]); return 1; }
    const char *src=argv[1]; const char *dst=argv[2];

    StmtList stmts; stmtlist_init(&stmts);
    VarList vars; varlist_init(&vars);

    if(parse_program(src,&stmts,&vars)!=0){ fprintf(stderr,"Failed to parse program\n"); return 1; }
    if(stmts.count==0){ printf("No statements.\n"); free_program(&stmts,&vars); return 0; }

    compute_usage_counts(&stmts,&vars);
    optimize_and_write_interactive(dst,&stmts,&vars);

    free_program(&stmts,&vars);
    return 0;
}
