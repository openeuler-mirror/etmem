#ifndef ETMEMD_PSI_H
#define ETMEMD_PSI_H

#include "uthash.h"

enum pid_param_state {
    STATE_NONE = 0,
    STATE_WORKING,
    STATE_REMOVE,
    STATE_FREE,
};

struct pressure {
    float avg10;
    float avg60;
    float avg300;
    unsigned long total;
};

struct memory_pressure {
    struct pressure some_pre;
    struct pressure full_pre;
};

struct cg_obj {
    double reclaim_rate;
    ino_t inode_num;
    char *path;
    struct cg_obj *next;
    UT_hash_handle hh;
    int gather;
    bool present;
};

struct psi_task_params {
    enum pid_param_state state;
    struct cg_obj *cg_hash; /* a cg_obj hashtable that takes inode as key */
    struct cg_obj *cg_list; /* a cg obj linked list for iteration */
    char *cg_dir;
    size_t cg_obj_cnt;
    double pressure; /* benchmark swap rate */
    double reclaim_rate;
    double reclaim_rate_max;
    double reclaim_rate_min;
    int gather;
    struct psi_eng_params *eng_params;
    unsigned long limit_min_bytes;
    unsigned long reclaim_max_bytes; /* max bytes every reclaim */
    double limit_min_ratio; /* ratio of memory.limit_in_bytes */
    struct psi_task_params *next;
};

struct psi_params_factory {
    pthread_mutex_t mtx;
    struct psi_task_params *to_add_head;
    struct psi_task_params *to_add_tail;
    struct psi_task_params *working_head;
};

struct psi_eng_params {
    unsigned long total_mem;
    int interval;
    pthread_t worker;
    struct psi_params_factory factory;
    bool finish;
};

int fill_engine_type_psi_fb(struct engine *eng, GKeyFile *config);

#endif
