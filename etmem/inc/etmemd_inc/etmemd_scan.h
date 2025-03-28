/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * etmem is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: louhongxiang
 * Create: 2019-12-10
 * Description: This is a header file of the function declaration for scan function.
 ******************************************************************************/

#ifndef ETMEMD_SCAN_H
#define ETMEMD_SCAN_H

#include <fcntl.h>
#include "etmemd.h"
#include "etmemd_task.h"
#include "etmemd_scan_exp.h"
#include "etmemd_common.h"

#define VMA_SEG_CNT_MAX         6
#define VMA_PERMS_STR_LEN       5
#define VMA_ADDR_STR_LEN        17
#define PAGE_SHIFT              12
#define EPT_IDLE_BUF_MIN        ((sizeof(u_int64_t) + 2) * 2)
#define PIP_CMD_SET_HVA         (unsigned char)((PIP_CMD << 4) & 0xF0)

#define MAPS_FILE               "/maps"
#define IDLE_SCAN_FILE          "/idle_pages"

#define SMAPS_FILE              "/smaps"
#define VMFLAG_HEAD             "VmFlags"

#define IDLE_SCAN_MAGIC         0x66
#define IDLE_SCAN_ADD_FLAGS     _IOW(IDLE_SCAN_MAGIC, 0x0, unsigned int)
#define VMA_SCAN_ADD_FLAGS      _IOW(IDLE_SCAN_MAGIC, 0x2, unsigned int)
#define ALL_SCAN_FLAGS          (SCAN_AS_HUGE | SCAN_IGN_HOST | VMA_SCAN_FLAG)
#ifdef ENABLE_PMU
#define PT_LEVEL_OFFEST          9
#define PTE_OFFSET               12
#define PMD_OFFEST               (PTE_OFFSET + PT_LEVEL_OFFEST)
#define PUD_OFFEST               (PMD_OFFEST + PT_LEVEL_OFFEST)
#endif

enum page_idle_type {
    PTE_ACCESS = 0,     /* 4k page */
    PMD_ACCESS,         /* 2M page */
    PUD_PRESENT,        /* 1G page */
    MAX_ACCESS = PUD_PRESENT,
    PTE_DIRTY,
    PMD_DIRTY,
    PTE_IDLE,
    PMD_IDLE,
    PMD_IDLE_PTES,      /* all PTE idle */
    PTE_HOLE,
    PMD_HOLE,
    PIP_CMD,            /* 10 0xa */
};

enum access_type_weight {
    IDLE_TYPE_WEIGHT = 0,
    READ_TYPE_WEIGHT = 1,
    WRITE_TYPE_WEIGHT = 3,
    MAX_ACCESS_WEIGHT = WRITE_TYPE_WEIGHT,
};

struct walk_address {
    uint64_t walk_start;                /* walk address start */
    uint64_t walk_end;                  /* walk address end */
    uint64_t last_walk_end;             /* last walk address end */
};

/* the caller need to judge value returned by etmemd_do_scan(), NULL means fail. */
struct page_refs *etmemd_do_scan(const struct task_pid *tpid, const struct task *tk);

struct pmu_params {
    uint64_t sample_period;         /* Sampling mem access events every N instructions */
    uint32_t vma_updata_rate;       /* Update after every N slide migrations */
    uint32_t cpu_set_size;          /* Number of CPU cores sampled by one thread */
    struct vma_info *vma_list;      /* Pointer to a linked list of VMA (Virtual Memory Area) information */
    struct page_refs *page_refs_head;             /* Pointer to the head of the page_refs linked list */
    struct sample_thread_meta *threads_meta_set;  /* Pointer to a set of sampled thread metadata */
    int vma_updata_count;                         /* Counter for VMA update operations */
    pthread_mutex_t vma_list_mutex;               /* Mutex for protecting access to the VMA list */
    unsigned int pid;
    int swap_flag;
};
#ifdef ENABLE_PMU
#define BITS_IN_INT (sizeof(int) * CHAR_BIT) // get the number of bits in an int
/* Assume the hardware events count following a power-law distribution */
static inline int limit_count_to_loop(int count, int loop)
{
    int log2 = (int)(BITS_IN_INT - __builtin_clz(count + 1));
    return loop < log2 ? loop : log2;
}
void merge_page_refs(struct pmu_params *pmu_params, struct page_sort **page_sort, struct memory_grade **memory_grade);

/* get the page_ref list from the buffer, if the pmu_sample thread has not been started, start the thread. */
struct page_refs *etmemd_do_sample(struct pmu_params *pmu_params);

/* stop pmu_sample thread when stopping the task. */
void etmemd_stop_sample(struct pmu_params *pmu_params);
#else
inline struct page_refs *etmemd_do_sample(struct pmu_params *pmu_params)
{
    return NULL;
}
inline void etmemd_stop_sample(struct pmu_params *pmu_params)
{
}
#endif

/* free vma list struct */
void free_vmas(struct vmas *vmas);

struct page_refs **walk_vmas(int fd, struct walk_address *walk_address, struct page_refs **pf, unsigned long *use_rss);
int get_page_refs(const struct vmas *vmas, const char *pid, struct page_refs **page_refs,
                  unsigned long *use_rss, struct ioctl_para *ioctl_para);

int split_vmflags(char ***vmflags_array, char *vmflags);
struct vmas *get_vmas_with_flags(const char *pid, char **vmflags_array, int vmflags_num, bool is_anon_only);
struct vmas *get_vmas(const char *pid);

void clean_page_refs_unexpected(void *arg);
void clean_memory_grade_unexpected(void *arg);

void clean_page_sort_unexpected(void *arg);
struct page_sort *alloc_page_sort(const struct task_pid *tk_pid);
struct page_sort *sort_page_refs(struct page_refs **page_refs, const struct task_pid *tk_pid);

struct page_refs *add_page_refs_into_memory_grade(struct page_refs *page_refs, struct page_refs **list);
int init_g_page_size(void);
int page_type_to_size(enum page_type type);
#endif
