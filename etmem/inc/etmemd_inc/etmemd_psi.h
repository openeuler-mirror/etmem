#ifndef ETMEMD_PSI_H
#define ETMEMD_PSI_H

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

struct psi_task_params {
    enum pid_param_state state;
    char *cg_path;
    double pressure;                        /* benchmark swap rate */
    double toleration;                      /* Dynamic accuracy */
    double reclaim_rate;
    double reclaim_rate_max;
    double reclaim_rate_min;
    int gather;
    struct psi_eng_params *eng_params;
    unsigned long limit_min_bytes;
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
