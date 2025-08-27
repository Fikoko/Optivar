/* debugger.c
 *
 * Optivar interactive debugger:
 *  - parse .optivar
 *  - for each variable ask: "Line N var 'name' is static? (y/n)"
 *  - load per-function signature from <funcname>.fnc
 *  - perform last-use analysis and automatic slot reuse
 *  - warn on static variable usage or arg mismatches
 *
 * Compile:
 *   gcc -std=c11 -O2 -o optivar-debug debugger.c
 *
 * Usage:
 *   ./optivar-debug program.optivar
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>

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

static void trace_printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}

/* Data structures */

typedef struct {
    char *name;
    int is_static;     // -1 unknown, 0 recyclable, 1 static
    int slot;          // slot index or -1
    int total_uses;
    int remaining_uses;
    int line_decl;
} Var;

typedef struct {
    char *func_name;
    char **args;
    int arg_count;
    char *lhs;
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

/* VarList utilities */
static void varlist_init(VarList *vl) { vl->items = NULL; vl->count = 0; vl->cap = 0; }
static void stmtlist_init(StmtList *sl) { sl->items = NULL; sl->count = 0; sl->cap = 0; }

static Var *varlist_find(VarList *vl, const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < vl->count; ++i) if (vl->items[i]->name && strcmp(vl->items[i]->name, name) == 0) return vl->items[i];
    return NULL;
}

static Var *varlist_add(VarList *vl, const char *name, int line) {
    Var *v = varlist_find(vl, name);
    if (v) return v;
    if (vl->count >= vl->cap) {
        vl->cap = vl->cap ? vl->cap * 2 : 32;
        vl->items = realloc(vl->items, sizeof(Var*) * vl->cap);
        if (!vl->items) { perror("realloc"); exit(1); }
    }
    v = malloc(sizeof(Var));
    v->name = strdup_safe(name);
    v->is_static = -1;
    v->slot = -1;
    v->total_uses = 0;
    v->remaining_uses = 0;
    v->line_decl = line;
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

/* Parser: read whole file, strip comments (--), split statements by ';' */

static char *read_file_all(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
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
        if (p[0] == '-' && p[1] == '-') {
            char *q = p;
            while (*q && *q != '\n') q++;
            memmove(p, q, strlen(q) + 1);
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
    char *rhs = strdup_safe(eq + 1); trim_inplace(rhs);
    // drop trailing ;
    int rl = (int)strlen(rhs);
    if (rl > 0 && rhs[rl-1] == ';') { rhs[rl-1] = '\0'; trim_inplace(rhs); }
    char *paren = strchr(rhs, '(');
    if (!paren) { free(lhs); free(rhs); return NULL; }
    *paren = '\0';
    char *fname = strdup_safe(rhs); trim_inplace(fname);
    char *args_area = strdup_safe(paren + 1);
    char *rc = strrchr(args_area, ')'); if (rc) *rc = '\0';
    trim_inplace(args_area);

    Stmt *s = malloc(sizeof(Stmt));
    s->func_name = strdup_safe(fname);
    s->lhs = strdup_safe(lhs);
    s->line_no = line_no;
    s->arg_count = 0;
    s->args = NULL;

    if (strlen(args_area) > 0) {
        char *save = NULL;
        char *tok = strtok_r(args_area, ",", &save);
        while (tok) {
            trim_inplace(tok);
            if (strlen(tok)) {
                s->args = realloc(s->args, sizeof(char*) * (s->arg_count + 1));
                s->args[s->arg_count++] = strdup_safe(tok);
            }
            tok = strtok_r(NULL, ",", &save);
        }
    }

    free(lhs); free(rhs); free(fname); free(args_area);
    return s;
}

static int parse_program(const char *path, StmtList *out_stmts, VarList *out_vars) {
    char *all = read_file_all(path);
    if (!all) return -1;
    strip_comments(all);
    char *p = all;
    char *start = p;
    int line_no = 1;
    for (; *p; ++p) {
        if (*p == '\n') ++line_no;
        if (*p == ';') {
            size_t len = p - start + 1;
            char *chunk = malloc(len + 1);
            memcpy(chunk, start, len);
            chunk[len] = '\0';
            char *work = strdup_safe(chunk);
            trim_inplace(work);
            if (strlen(work) > 0) {
                Stmt *s = parse_statement(work, line_no);
                if (s) {
                    stmtlist_add(out_stmts, s);
                    varlist_add(out_vars, s->lhs, s->line_no);
                    for (int i = 0; i < s->arg_count; ++i) varlist_add(out_vars, s->args[i], s->line_no);
                }
            }
            free(chunk); free(work);
            start = p + 1;
        }
    }
    free(all);
    return 0;
}

/* Compute usage counts (how many times each var appears as arg across program) */

static void compute_usage_counts(StmtList *stmts, VarList *vars) {
    for (int i = 0; i < vars->count; ++i) { vars->items[i]->total_uses = 0; vars->items[i]->remaining_uses = 0; }
    for (int si = 0; si < stmts->count; ++si) {
        Stmt *s = stmts->items[si];
        for (int a = 0; a < s->arg_count; ++a) {
            Var *v = varlist_find(vars, s->args[a]);
            if (v) v->total_uses++;
        }
    }
    for (int i = 0; i < vars->count; ++i) vars->items[i]->remaining_uses = vars->items[i]->total_uses;
}

/* interactive prompt to mark var static or recyclable */

static void interactive_static_prompt(VarList *vars) {
    char buf[64];
    for (int i = 0; i < vars->count; ++i) {
        Var *v = vars->items[i];
        if (v->is_static != -1) continue;
        printf("Line %d var '%s' is static? (y/n): ", v->line_decl, v->name);
        if (!fgets(buf, sizeof(buf), stdin)) { strcpy(buf, "n\n"); }
        char c = 'n';
        for (int j = 0; buf[j]; ++j) { if (!isspace((unsigned char)buf[j])) { c = buf[j]; break; } }
        v->is_static = (c == 'y' || c == 'Y') ? 1 : 0;
    }
}

/* Function signature loader from <funcname>.fnc
   Reads signature only (no code) to validate args.
   Return: 0 success, -1 on error. On success, *expected_names is allocated array of char*, caller must free them.
*/
static int load_fnc_signature(const char *funcname, char ***expected_names, int *out_arg_count) {
    // filename = funcname + ".fnc"
    size_t fnlen = strlen(funcname) + 5;
    char *fname = malloc(fnlen);
    snprintf(fname, fnlen, "%s.fnc", funcname);
    FILE *f = fopen(fname, "rb");
    if (!f) { free(fname); return -1; }
    free(fname);

    // read magic
    char magic[4];
    if (fread(magic, 1, 4, f) != 4) { fclose(f); return -1; }
    if (memcmp(magic, "FNC1", 4) != 0) { fclose(f); return -1; }

    uint16_t name_len = 0;
    if (fread(&name_len, sizeof(uint16_t), 1, f) != 1) { fclose(f); return -1; }
    char *name = malloc(name_len + 1);
    if (fread(name, 1, name_len, f) != name_len) { free(name); fclose(f); return -1; }
    name[name_len] = '\0';
    // we don't need to check name equals funcname, but could

    uint16_t arg_count = 0;
    if (fread(&arg_count, sizeof(uint16_t), 1, f) != 1) { free(name); fclose(f); return -1; }

    char **expect = NULL;
    if (arg_count > 0) {
        expect = malloc(sizeof(char*) * arg_count);
        for (int i = 0; i < arg_count; ++i) {
            uint16_t alen = 0;
            if (fread(&alen, sizeof(uint16_t), 1, f) != 1) { for (int k=0;k<i;k++) free(expect[k]); free(expect); free(name); fclose(f); return -1; }
            char *an = malloc(alen + 1);
            if (fread(an, 1, alen, f) != alen) { free(an); for (int k=0;k<i;k++) free(expect[k]); free(expect); free(name); fclose(f); return -1; }
            an[alen] = '\0';
            expect[i] = an;
        }
    }

    // skip code size and code (we only need signature here)
    // read code_size to seek past code
    uint32_t code_size = 0;
    if (fread(&code_size, sizeof(uint32_t), 1, f) == 1) {
        if (code_size > 0) fseek(f, code_size, SEEK_CUR);
    }

    free(name);
    fclose(f);
    *expected_names = expect;
    *out_arg_count = (int)arg_count;
    return 0;
}

/* ---------- Slot state and allocation for simulation ---------- */

typedef struct {
    char **slots;    // slot index -> var name (string) or NULL
    int capacity;
    int *used;       // 1 if occupied
    int *free_stack; // indices
    int free_top;
} SlotState;

static void slotstate_init(SlotState *ss) { ss->slots = NULL; ss->capacity = 0; ss->used = NULL; ss->free_stack = NULL; ss->free_top = 0; }

static void slotstate_ensure(SlotState *ss, int need) {
    if (ss->capacity >= need) return;
    int newc = ss->capacity ? ss->capacity * 2 : 8;
    while (newc < need) newc *= 2;
    ss->slots = realloc(ss->slots, sizeof(char*) * newc);
    ss->used = realloc(ss->used, sizeof(int) * newc);
    for (int i = ss->capacity; i < newc; ++i) { ss->slots[i] = NULL; ss->used[i] = 0; }
    ss->capacity = newc;
}

static int slot_pop_free(SlotState *ss) {
    if (ss->free_top == 0) return -1;
    return ss->free_stack[--ss->free_top];
}

static void slot_push_free(SlotState *ss, int idx) {
    ss->free_stack = realloc(ss->free_stack, sizeof(int) * (ss->free_top + 1));
    ss->free_stack[ss->free_top++] = idx;
}

static int allocate_slot(SlotState *ss, const char *varname) {
    int idx = slot_pop_free(ss);
    if (idx >= 0) {
        if (ss->slots[idx]) free(ss->slots[idx]);
        ss->slots[idx] = strdup_safe(varname);
        ss->used[idx] = 1;
        return idx;
    }
    // find first unused
    for (int i = 0; i < ss->capacity; ++i) {
        if (!ss->used[i]) {
            if (ss->slots[i]) free(ss->slots[i]);
            ss->slots[i] = strdup_safe(varname);
            ss->used[i] = 1;
            return i;
        }
    }
    // extend
    int old = ss->capacity;
    slotstate_ensure(ss, old + 1);
    ss->slots[old] = strdup_safe(varname);
    ss->used[old] = 1;
    return old;
}

static void free_slot(SlotState *ss, int idx) {
    if (idx < 0 || idx >= ss->capacity) return;
    if (!ss->used[idx]) return;
    ss->used[idx] = 0;
    slot_push_free(ss, idx);
}

/* ---------- simulate and optimize (trace) ---------- */

static void simulate_and_optimize(StmtList *stmts, VarList *vars) {
    SlotState ss; slotstate_init(&ss);
    for (int i = 0; i < vars->count; ++i) vars->items[i]->slot = -1;

    trace_printf("\n[Simulation & optimization trace]\n");
    for (int si = 0; si < stmts->count; ++si) {
        Stmt *s = stmts->items[si];
        trace_printf("\nLine %d: %s = %s(", s->line_no, s->lhs, s->func_name);
        for (int a = 0; a < s->arg_count; ++a) { if (a) trace_printf(", "); trace_printf("%s", s->args[a]); }
        trace_printf(")\n");

        // load signature for this function (if exists)
        char **expected = NULL;
        int exp_count = 0;
        int sig_ok = (load_fnc_signature(s->func_name, &expected, &exp_count) == 0);

        // warn on arg count mismatch
        if (sig_ok) {
            if (exp_count != s->arg_count) {
                trace_printf("  Warning: function '%s' expects %d args but %d given\n",
                             s->func_name, exp_count, s->arg_count);
            }
            // validate arg names per position: expected name or "*" wildcard
            int minc = (exp_count < s->arg_count) ? exp_count : s->arg_count;
            for (int a = 0; a < minc; ++a) {
                const char *expected_name = expected[a];
                const char *given = s->args[a];
                if (strcmp(expected_name, "*") != 0 && strcmp(expected_name, given) != 0) {
                    trace_printf("  Warning: arg %d for '%s' expected '%s' but got '%s'\n",
                                 a+1, s->func_name, expected_name, given);
                }
            }
        } else {
            trace_printf("  (No signature file for '%s' found; skipping signature check)\n", s->func_name);
        }

        // warn if any arg is static
        for (int a = 0; a < s->arg_count; ++a) {
            Var *av = varlist_find(vars, s->args[a]);
            if (av && av->is_static == 1) {
                trace_printf("  Warning: Var '%s' is static therefore cannot be passed into %s()\n",
                             av->name, s->func_name);
            }
        }

        // lhs var record
        Var *lhs = varlist_find(vars, s->lhs);
        if (!lhs) lhs = varlist_add(vars, s->lhs, s->line_no);

        // determine slot for lhs:
        if (lhs->slot != -1) {
            trace_printf("  [REUSE SLOT %d] lhs '%s' reuses its slot\n", lhs->slot, lhs->name);
        } else {
            // try last-use reuse: find an arg that will be dead after this use and recyclable
            int reuse_slot = -1;
            int reuse_arg_index = -1;
            for (int a = 0; a < s->arg_count; ++a) {
                Var *av = varlist_find(vars, s->args[a]);
                if (!av) continue;
                if (av->remaining_uses == 1 && av->slot != -1 && av->is_static == 0) {
                    reuse_slot = av->slot;
                    reuse_arg_index = a;
                    break;
                }
            }
            if (reuse_slot != -1) {
                if (ss.slots[reuse_slot]) { free(ss.slots[reuse_slot]); ss.slots[reuse_slot] = NULL; }
                ss.slots[reuse_slot] = strdup_safe(lhs->name);
                ss.used[reuse_slot] = 1;
                lhs->slot = reuse_slot;
                trace_printf("  [REUSE ARG SLOT %d] lhs '%s' reuses slot of arg '%s'\n",
                             reuse_slot, lhs->name, s->args[reuse_arg_index]);
            } else {
                int new_slot = allocate_slot(&ss, lhs->name);
                lhs->slot = new_slot;
                trace_printf("  [ALLOC SLOT %d] for lhs '%s'\n", new_slot, lhs->name);
            }
        }

        // consume arg uses and free slots for args that become dead
        for (int a = 0; a < s->arg_count; ++a) {
            Var *av = varlist_find(vars, s->args[a]);
            if (!av) continue;
            if (av->remaining_uses > 0) av->remaining_uses--;
            trace_printf("    arg '%s' remaining_uses -> %d\n", av->name, av->remaining_uses);
            if (av->remaining_uses == 0 && av->is_static == 0 && av->slot != -1) {
                trace_printf("    [FREE SLOT %d] var '%s' no longer used, freed\n", av->slot, av->name);
                free_slot(&ss, av->slot);
                av->slot = -1;
            }
        }

        if (expected) {
            for (int i = 0; i < exp_count; ++i) free(expected[i]);
            free(expected);
        }
    }

    // final live slots
    trace_printf("\n[Final live slots]\n");
    for (int i = 0; i < ss.slot_capacity; ++i) {
        if (ss.used[i] && ss.slots[i]) trace_printf("  slot %d -> %s\n", i, ss.slots[i]);
    }

    // cleanup
    for (int i = 0; i < ss.slot_capacity; ++i) if (ss.slots[i]) free(ss.slots[i]);
    free(ss.slots); free(ss.used); free(ss.free_stack);
}

/* cleanup program memory */
static void free_program(StmtList *sl, VarList *vl) {
    for (int i = 0; i < sl->count; ++i) {
        Stmt *s = sl->items[i];
        free(s->func_name); free(s->lhs);
        for (int j = 0; j < s->arg_count; ++j) free(s->args[j]);
        free(s->args); free(s);
    }
    free(sl->items);
    for (int i = 0; i < vl->count; ++i) { free(vl->items[i]->name); free(vl->items[i]); }
    free(vl->items);
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s program.optivar\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];

    StmtList stmts; stmtlist_init(&stmts);
    VarList vars; varlist_init(&vars);

    if (parse_program(path, &stmts, &vars) != 0) {
        fprintf(stderr, "Failed to parse program\n");
        return 1;
    }
    if (stmts.count == 0) { printf("No statements.\n"); free_program(&stmts, &vars); return 0; }

    compute_usage_counts(&stmts, &vars);
    interactive_static_prompt(&vars);

    printf("\n[Static decision summary]\n");
    for (int i = 0; i < vars.count; ++i) {
        Var *v = vars.items[i];
        printf("  var '%s' (line %d) -> %s\n", v->name, v->line_decl, v->is_static == 1 ? "STATIC" : "RECYCLABLE");
    }

    simulate_and_optimize(&stmts, &vars);

    free_program(&stmts, &vars);
    return 0;
}
