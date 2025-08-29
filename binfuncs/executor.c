#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>

typedef struct VarSlot {
    void* data;
    int in_use;
    int last_use;
    int constant;
    long value;
    pthread_mutex_t lock;
} VarSlot;

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

typedef struct {
    IRStmt* stmts;
    int stmt_count;
    VarSlot** env_array;
    int* remaining;
    int max_threads;
    pthread_mutex_t* mutex;
    pthread_cond_t* cond;
} ExecArgs;

static void execute_stmt(IRStmt* s, VarSlot** env_array) {
    if(s->dead || s->executed) return;
    VarSlot* lhs = env_array[s->lhs_index];

    if(s->inlined){
        long val = 0;
        for(int i=0;i<s->argc;i++){
            VarSlot* arg = env_array[s->arg_indices[i]];
            val += arg->constant ? arg->value : (long)arg->data;
        }
        lhs->value = val;
        lhs->constant = 0;
        s->executed = 1;
        return;
    }

    long* args_values = malloc(sizeof(long) * s->argc);
    for(int i=0;i<s->argc;i++){
        VarSlot* arg = env_array[s->arg_indices[i]];
        args_values[i] = arg->constant ? arg->value : (long)arg->data;
    }

    void (*fn)(long*, long*) = s->func_ptr;
    pthread_mutex_lock(&lhs->lock);
    fn(&lhs->value, args_values);
    lhs->constant = 0;
    pthread_mutex_unlock(&lhs->lock);

    free(args_values);
    s->executed = 1;
}

static void* thread_worker(void* arg){
    ExecArgs* ea = (ExecArgs*)arg;
    int progress;

    do{
        progress = 0;
        for(int i=0;i<ea->stmt_count;i++){
            IRStmt* s = &ea->stmts[i];
            if(s->dead || s->executed) continue;

            int ready = 1;
            for(int d=0; d<s->dep_count; d++){
                if(!ea->stmts[s->dep_indices[d]].executed){
                    ready = 0; break;
                }
            }

            if(ready){
                execute_stmt(s, ea->env_array);
                progress = 1;
                pthread_mutex_lock(ea->mutex);
                (*ea->remaining)--;
                pthread_cond_broadcast(ea->cond);
                pthread_mutex_unlock(ea->mutex);
            }
        }

        if(!progress){
            pthread_mutex_lock(ea->mutex);
            if(*ea->remaining>0) pthread_cond_wait(ea->cond, ea->mutex);
            pthread_mutex_unlock(ea->mutex);
        }

    }while(*ea->remaining>0);

    return NULL;
}

// Function called by loader
void executor(IRStmt* stmts, int stmt_count, VarSlot** env_array, int max_threads){
    pthread_t threads[max_threads];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    int remaining = stmt_count;

    ExecArgs args = { stmts, stmt_count, env_array, &remaining, max_threads, &mutex, &cond };

    for(int t=0; t<max_threads; t++)
        pthread_create(&threads[t], NULL, thread_worker, &args);

    for(int t=0; t<max_threads; t++)
        pthread_join(threads[t], NULL);
}
