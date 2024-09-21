/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * etmem is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zpw11
 * Create: 2023-10-10
 * Description: Etmemd pmu sample.
 ******************************************************************************/

#ifdef ENABLE_PMU
#include <complex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <pfmlib.h>

#include "etmemd_task.h"
#include "etmemd_scan.h"
#include "etmemd_log.h"
#include "securec.h"

#define INIT_SAMPLE_PERIOD       5000
#define PAGE_SIZE                4096
#define RING_BUFFER_PAGES        64
#define MMAP_SIZE                ((1 + RING_BUFFER_PAGES) * PAGE_SIZE)
#define SYS_CORES                sysconf(_SC_NPROCESSORS_ONLN)
#define PERF_PRECISE_IP          3
#define PERF_LEFT_SHIFT          4

enum sample_thread_status {
    SAMPLE_THREAD_RUNNING = 0,
    SAMPLE_THREAD_STOP,
};

enum EVENT_TYPE {
    DDR_LOAD,
    DDR_STORE,
    EVENT_NUM
};

enum ARCH_TYPE {
    ARM64,
    X86,
    POWERPC,
    ARCH_NUM,
};

struct perf_sample {
    struct perf_event_header header;
    uint64_t id;
    uint64_t address;
    uint32_t cpu;
};

struct perf_cpu_monitor {
    int fd;        /* perf event file descriptor. */
    unsigned size; /* buffer size used. */
    void *buffer;  /* pointer points to the allocated memory space. */
};

struct sample_thread_meta {
    pthread_t *tid; /* thread id. */
    enum sample_thread_status status; /* thread status. */
};

struct sample_thread_args {
    struct perf_cpu_monitor **perf_cpu_monitors;
    int cpu_set_size; /* Specifies the number of CPU cores sampled by one thread. */
    int cpu_set_index; /* Specifies the index of the CPU core set. */
    struct pmu_params *pmu_params;
};

struct vma_info {
    uint64_t start_addr;        /* vma start address */
    uint64_t length;            /* vma length */
    struct page_refs **pages; /* array of page_refs pointers */
    pthread_mutex_t node_mutex; /* page_ref array mutex */
    struct vma_info *next;      /* point to next vma */
};

const char *g_event_name[EVENT_NUM] = {"DDR_LOAD", "DDR_STORE"};
const char *g_events[EVENT_NUM][ARCH_NUM] = {
    {   "MEM_ACCESS_RD", // arm64
        "MEM_UOPS_RETIRED.ALL_LOADS", // x86
        "PM_MEM_READ", // powerpc
    },
    {   "MEM_ACCESS_WR", // arm64
        "MEM_UOPS_RETIRED.ALL_STORES", // x86
        "PM_MEM_RWITM", // powerpc
    }
};

static struct vma_info *get_vma_info(struct pmu_params *pmu_params, uint64_t addr)
{
    struct vma_info *node;

    pthread_mutex_lock(&(pmu_params->vma_list_mutex));
    for (node = pmu_params->vma_list; node != NULL; node = node->next) {
        if (addr >= node->start_addr && addr < node->start_addr + node->length) {
            pthread_mutex_unlock(&(pmu_params->vma_list_mutex));
            return node;
        }
    }
    pthread_mutex_unlock(&(pmu_params->vma_list_mutex));
    return NULL;
}

static struct page_refs *get_page_refs_form_list(struct pmu_params *pmu_params, uint64_t addr)
{
    struct vma_info *node;
    struct page_refs *page;
    unsigned index;
    int i;
    node = get_vma_info(pmu_params, addr);
    if (node == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&(node->node_mutex));
    for (i = 0; i < PAGE_TYPE_INVAL; i++) {
        index = (addr - node->start_addr) >> (PTE_OFFSET + i * PT_LEVEL_OFFEST);
        page = node->pages[index];
        if (page != NULL) {
            pthread_mutex_unlock(&(node->node_mutex));
            return page;
        }
    }
    pthread_mutex_unlock(&(node->node_mutex));
    return NULL;
}

static void free_vma_list(struct vma_info *vma_list, struct vma_info *node)
{
    struct vma_info *prev = NULL;
    struct vma_info *current = vma_list;

    if (node != NULL) {
        free(node);
    }
    while (current != NULL) {
        prev = current;
        current = current->next;
        free(prev->pages);
        free(prev);
    }
}

static int update_vmas_new(struct pmu_params *pmu_params, struct vmas *vmas)
{
    struct vma *tmp_vma = vmas->vma_list;

    while (tmp_vma != NULL) {
        struct vma_info *node = (struct vma_info *)calloc(1, sizeof(struct vma_info));
        if (node == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc for vma_info fail\n");
            free_vma_list(pmu_params->vma_list, node);
            return -1;
        }

        node->start_addr = tmp_vma->start;
        node->length = tmp_vma->end - tmp_vma->start;
        node->pages = (struct page_refs **)calloc(node->length / PAGE_SIZE, sizeof(struct page_refs *));
        if (node->pages == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc for vma_info pages fail\n");
            free_vma_list(pmu_params->vma_list, node);
            return -1;
        }

        pthread_mutex_init(&(node->node_mutex), NULL);
        pthread_mutex_lock(&(pmu_params->vma_list_mutex));
        node->next = pmu_params->vma_list;
        pmu_params->vma_list = node;
        pthread_mutex_unlock(&(pmu_params->vma_list_mutex));
        tmp_vma = tmp_vma->next;
    }
    return 0;
}

static struct page_refs *update_page_refs_in_vma_new(struct page_refs *page_refs, struct vma_info **vma_info)
{
    struct page_refs *pf;
    unsigned index;

    if (vma_info == NULL || (*vma_info)->pages == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "vma_info is null\n");
        return NULL;
    }

    if (page_refs == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "page_refs is null\n");
        return NULL;
    }

    pthread_mutex_lock(&((*vma_info)->node_mutex));
    pf = page_refs;
    while (pf != NULL && pf->addr >= (*vma_info)->start_addr &&
           pf->addr < (*vma_info)->start_addr + (*vma_info)->length) {
        index = (pf->addr - (*vma_info)->start_addr) >> (PTE_OFFSET);
        (*vma_info)->pages[index] = pf;
        pf = pf->next;
    }
    pthread_mutex_unlock(&((*vma_info)->node_mutex));
    return pf;
}

static void update_page_refs(struct pmu_params *pmu_params, struct page_refs *page_refs)
{
    struct page_refs *tmp_page_refs = page_refs;
    struct vma_info *vma_info = NULL;

    while (tmp_page_refs != NULL) {
        vma_info = get_vma_info(pmu_params, tmp_page_refs->addr);
        if (vma_info == NULL) {
            tmp_page_refs = tmp_page_refs->next;
            continue;
        }
        tmp_page_refs = update_page_refs_in_vma_new(tmp_page_refs, &vma_info);
    }
}

static void clear_old_vmas(struct pmu_params *pmu_params)
{
    struct vma_info *node = pmu_params->vma_list;
    struct vma_info *tmp_node = NULL;

    pthread_mutex_lock(&(pmu_params->vma_list_mutex));
    while (node != NULL) {
        tmp_node = node;
        node = node->next;
        pthread_mutex_lock(&(tmp_node->node_mutex));
        free(tmp_node->pages);
        pthread_mutex_unlock(&(tmp_node->node_mutex));
        pthread_mutex_destroy(&(tmp_node->node_mutex));
        free(tmp_node);
        tmp_node = NULL;
    }
    pthread_mutex_unlock(&(pmu_params->vma_list_mutex));
    pmu_params->vma_list = NULL;
}

/* Retrieve page reference data from the process's virtual memory addresses.
 * Merge the retrieved data into the index. */
static int update_page_refs_from_vma(struct pmu_params *pmu_params,
                                     struct page_refs **page_refs, bool flag)
{
    struct page_refs *tmp_pf = NULL;
    struct vmas *vmas = NULL;
    struct ioctl_para ioctl_para = {0};
    uint64_t ret;
    int sampled_pid = pmu_params->pid;
    char pid[PID_STR_MAX_LEN] = {0};

    if (snprintf_s(pid, PID_STR_MAX_LEN, PID_STR_MAX_LEN - 1, "%u", sampled_pid) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf pid fail %u", sampled_pid);
        return -1;
    }

    vmas = get_vmas(pid);
    if (vmas == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "get vmas for %s fail\n", pid);
        return -1;
    }

    ioctl_para.ioctl_cmd = VMA_SCAN_ADD_FLAGS;
    if (pmu_params->swap_flag != 0) {
        ioctl_para.ioctl_parameter = VMA_SCAN_FLAG;
    }

    ret = get_page_refs(vmas, pid, &tmp_pf, NULL, &ioctl_para);
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "pmu_get_page_refs form %s fail\n", pid);
        free_vmas(vmas);
        return ret;
    }

    if (flag) {
        clear_old_vmas(pmu_params);
        pthread_mutex_lock(&(pmu_params->vma_list_mutex));
        clean_page_refs_unexpected(page_refs);
        pthread_mutex_unlock(&(pmu_params->vma_list_mutex));
    }

    ret = update_vmas_new(pmu_params, vmas);
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "update_vmas for %s fail\n", pid);
        free_vmas(vmas);
        return ret;
    }

    update_page_refs(pmu_params, tmp_pf);
    (*page_refs) = tmp_pf;

    free_vmas(vmas);
    return 0;
}

static void clear_vma_info_list(struct pmu_params *pmu_params)
{
    struct vma_info *current = NULL;
    struct vma_info *tmp = NULL;

    pthread_mutex_lock(&(pmu_params->vma_list_mutex));
    current = pmu_params->vma_list;
    while (current != NULL) {
        tmp = current;
        current = current->next;
        pthread_mutex_lock(&(tmp->node_mutex));
        if (tmp->pages != NULL) {
            free(tmp->pages);
            tmp->pages = NULL;
        }
        pthread_mutex_unlock(&(tmp->node_mutex));
        pthread_mutex_destroy(&(tmp->node_mutex));
        free(tmp);
        tmp = NULL;
    }
    pmu_params->vma_list = NULL;
    pthread_mutex_unlock(&(pmu_params->vma_list_mutex));
    pthread_mutex_destroy(&(pmu_params->vma_list_mutex));
}

static unsigned long perf_process_event_code(const char **events)
{
    int i;
    int j;
    int ret;
    unsigned long hexvalue = 0x0;
    pfm_pmu_encode_arg_t arg;

    if (events == NULL) {
        return 0;
    }

    ret = pfm_initialize();
    if (ret != PFM_SUCCESS) {
        etmemd_log(ETMEMD_LOG_ERR, "pfm_initialize fail\n");
        return 0;
    }

    ret = memset_s(&arg, sizeof(arg), 0, sizeof(arg));
    if (ret != EOK) {
        etmemd_log(ETMEMD_LOG_ERR, "memset_s pfm_pmu_encode_arg_t arg fail\n");
        return 0;
    }

    for (i = 0; i < ARCH_NUM; i++) {
        char *fqstr = NULL;
        arg.fstr = &fqstr;

        ret = pfm_get_os_event_encoding(events[i], PFM_PLM0 | PFM_PLM3, PFM_OS_NONE, &arg);
        if (ret != PFM_SUCCESS) {
            continue;
        }

        hexvalue = 0x0;
        for (j = 0; j < arg.count; j++) {
            hexvalue = (hexvalue << PERF_LEFT_SHIFT) | arg.codes[j];
        }
        free(fqstr);
    }

    if (arg.codes) {
        free(arg.codes);
    }
    return hexvalue;
}

static int perf_process_events_code(uint64_t *events_code)
{
    int i;
    
    for (i = 0; i < EVENT_NUM; i++) {
        events_code[i] = perf_process_event_code(g_events[i]);
        if (events_code[i] == 0) {
            etmemd_log(ETMEMD_LOG_ERR, "Process %s event code fail. Currently, \
            the system only supports three architectures: arm64, x86, and powerpc.\n", g_event_name[i]);
            return -1;
        }
    }

    return 0;
}

static inline int perf_event_open(struct perf_event_attr *attr,
                                  pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int init_perf_cpu_monitor(struct perf_cpu_monitor *cpu_monitor, int cpu, uint64_t type, int pid)
{
    int perf_fd = -1;
    int ret;
    void *sample_buffer = NULL;
    struct perf_event_attr attr;
    uint64_t id;

    ret = memset_s(&attr, sizeof(struct perf_event_attr), 0, sizeof(struct perf_event_attr));
    if (ret != EOK) {
        etmemd_log(ETMEMD_LOG_ERR, "memset_s perf_event_attr attr fail, errno = %s\n", strerror(errno));
        return -errno;
    }

    attr.type = PERF_TYPE_RAW;
    attr.config = (uint64_t)type;
    attr.size = sizeof(struct perf_event_attr);
    attr.sample_period = INIT_SAMPLE_PERIOD;
    attr.sample_type = PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.precise_ip = PERF_PRECISE_IP;
    attr.wakeup_events = 1;
    attr.inherit = 1;

    perf_fd = perf_event_open(&attr, pid, cpu, -1, 0);
    if (perf_fd < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "perf_event_open fail in cpu monitor %d, errno = %s\n", cpu, strerror(errno));
        return -errno;
    }

    sample_buffer = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (sample_buffer == MAP_FAILED) {
        etmemd_log(ETMEMD_LOG_ERR, "mmap fail in cpu monitor %d, errno = %s\n", cpu, strerror(errno));
        return -errno;
    }

    ret = ioctl(perf_fd, PERF_EVENT_IOC_ID, &id);
    if (ret < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "ioctl fail in cpu monitor %d, errno = %s\n", cpu, strerror(errno));
        return -errno;
    }

    cpu_monitor->fd = perf_fd;
    cpu_monitor->buffer = sample_buffer;
    cpu_monitor->size = 0;
    return 0;
}

static int perf_set_cpu_sample_period(struct perf_cpu_monitor *cpu_monitor, unsigned long period)
{
    int ret;
    if (period == 0) {
        ret = ioctl(cpu_monitor->fd, PERF_EVENT_IOC_DISABLE, 0);
        if (ret < 0) {
            etmemd_log(ETMEMD_LOG_ERR, "set sample period ioctl DISABLE fail, errno = %s\n", strerror(errno));
            return -errno;
        }
        return 0;
    }

    ret = ioctl(cpu_monitor->fd, PERF_EVENT_IOC_PERIOD, &period);
    if (ret < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "set sample period ioctl PERIOD fail, errno = %s\n", strerror(errno));
        return -errno;
    }

    ret = ioctl(cpu_monitor->fd, PERF_EVENT_IOC_ENABLE, 0);
    if (ret < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "set sample period ioctl ENABLE fail, errno = %s\n", strerror(errno));
        return -errno;
    }

    return 0;
}

static int clear_perf_cpu_monitor(struct perf_cpu_monitor *perf_cpu_monitor)
{
    int ret = 0;

    if (perf_cpu_monitor->buffer != NULL) {
        ret = munmap(perf_cpu_monitor->buffer, MMAP_SIZE);
        if (ret != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "munmap fail when clear the perf_cpu_monitor\n");
        }
    }

    if (perf_cpu_monitor->fd != -1) {
        ret = close(perf_cpu_monitor->fd);
        if (ret != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "close perf fd fail when clear the perf_cpu_monitor\n");
        }
    }

    perf_cpu_monitor->fd = -1;
    perf_cpu_monitor->buffer = NULL;
    perf_cpu_monitor->size = 0;
    return ret;
}

static void clear_perf_cpu_monitors(struct perf_cpu_monitor **perf_cpu_monitors)
{
    int i;
    int j;
    int ret;

    for (i = 0; i < EVENT_NUM; i++) {
        if (perf_cpu_monitors[i] == NULL) {
            continue;
        }
        for (j = 0; j < SYS_CORES; j++) {
            ret = clear_perf_cpu_monitor(&perf_cpu_monitors[i][j]);
            if (ret != 0) {
                etmemd_log(ETMEMD_LOG_ERR, "%s event monitor of cpu %d clear fail.", g_event_name[i], j);
            }
        }
        free(perf_cpu_monitors[i]);
    }
    free(perf_cpu_monitors);
}

static struct perf_cpu_monitor **init_perf_cpu_monitors(unsigned long period,
                                                        uint64_t *events_code, int pid)
{
    int i;
    int j;
    int ret;

    struct perf_cpu_monitor **cpus_monitors = (struct perf_cpu_monitor**)calloc(EVENT_NUM, \
        sizeof(struct perf_cpu_monitor*));
    if (cpus_monitors == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc cpus_monitors fail\n");
        return NULL;
    }
    for (i = 0; i < EVENT_NUM; i++) {
        cpus_monitors[i] = (struct perf_cpu_monitor*)calloc(SYS_CORES, sizeof(struct perf_cpu_monitor));
        if (cpus_monitors[i] == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc cpus_monitors for per event fail\n");
            goto monitor_out;
        }
    }

    for (i = 0; i < EVENT_NUM; i++) {
        for (j = 0; j < SYS_CORES; j++) {
            ret = init_perf_cpu_monitor(&cpus_monitors[i][j], j, events_code[i], pid);
            if (ret != 0) {
                etmemd_log(ETMEMD_LOG_ERR, "init_perf_cpu_monitor fail in cpu monitor %d\n", i);
                goto monitor_out;
            }

            ret = perf_set_cpu_sample_period(&cpus_monitors[i][j], period);
            if (ret != 0) {
                etmemd_log(ETMEMD_LOG_ERR, "perf_set_cpu_sample_period fail in cpu monitor %d\n", i);
                goto monitor_out;
            }
        }
    }

    return cpus_monitors;

monitor_out:
    clear_perf_cpu_monitors(cpus_monitors);

    return NULL;
}

static int get_sample_event(struct perf_cpu_monitor *cpu_monitor, uint64_t *address)
{
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page*)(cpu_monitor->buffer);
    uint64_t tail = meta->data_tail;
    uint64_t head = meta->data_head;

    if (tail == head) {
        return -1;
    }

    while (tail < head) {
        uint64_t position = tail % (PAGE_SIZE * RING_BUFFER_PAGES);
        /* perf_event_mmap_page exclusively uses the first shared memory page.
         * Offset adjustment by PAGE_SIZE required. */
        struct perf_sample *entry = (struct perf_sample*)((char*)(cpu_monitor->buffer) + PAGE_SIZE + position);
        tail += entry->header.size;
        cpu_monitor->size = (cpu_monitor->size + entry->header.size) % (PAGE_SIZE * RING_BUFFER_PAGES);
        if (cpu_monitor->size <= (unsigned)sizeof(struct perf_sample)) {
            continue;
        }
        if (entry->header.type == PERF_RECORD_SAMPLE && entry->address != 0) {
            *address = entry->address;
            meta->data_tail = tail;
            return 0;
        }
    }
    meta->data_tail = tail;

    return -1;
}

static void *get_event_addr(struct perf_cpu_monitor *cpu_monitor)
{
    uint64_t address;
    int ret;

    ret = get_sample_event(cpu_monitor, &address);
    if (ret < 0) {
        return NULL;
    }

    return (void*)address;
}

static void parse_sample_record(struct pmu_params *pmu_params, struct perf_cpu_monitor *cpu_monitor)
{
    void *address = NULL;
    struct page_refs *page = NULL;
    if (cpu_monitor == NULL) {
        return;
    }

    address = get_event_addr(cpu_monitor);
    if (address != NULL) {
        page = get_page_refs_form_list(pmu_params, (uint64_t)address);
        if (page == NULL) {
            return;
        } else {
            page->count++;
            return;
        }
    }

    return;
}

/* This function continuously monitors specified performance events on designated CPU cores.
 * Breaking the loop if the thread's status is set to stop. */
static void *pmu_sample_thread(void *arg)
{
    struct sample_thread_args *thread_args = (struct sample_thread_args *)arg;
    struct perf_cpu_monitor **cpu_monitors_set = thread_args->perf_cpu_monitors;
    int cpu_set_size = thread_args->cpu_set_size;
    int cpu_set_index = thread_args->cpu_set_index;
    int start_monitor_index = cpu_set_index * cpu_set_size;
    struct pmu_params *pmu_params = thread_args->pmu_params;
    int i;
    int j;

    pmu_params->threads_meta_set[cpu_set_index].status = SAMPLE_THREAD_RUNNING;
    while (1) {
        if (pmu_params->threads_meta_set[cpu_set_index].status == SAMPLE_THREAD_STOP) {
            break;
        }
        for (i = 0; i < EVENT_NUM; i++) {
            for (j = 0; j < cpu_set_size; j++) {
                parse_sample_record(pmu_params, &cpu_monitors_set[i][start_monitor_index + j]);
            }
        }
    }

    if (cpu_set_index == 0) {
        clear_perf_cpu_monitors(cpu_monitors_set);
    }

    return NULL;
}

static void pmu_threads_out(struct pmu_params *pmu_params, int cpu_set_count)
{
    int i;
    for (i = cpu_set_count - 1; i >= 0; i--) {
        if (pmu_params->threads_meta_set[i].tid == NULL) {
            continue;
        }
        pmu_params->threads_meta_set[i].status = SAMPLE_THREAD_STOP;
        pthread_join(*(pmu_params->threads_meta_set[i].tid), NULL);
        free(pmu_params->threads_meta_set[i].tid);
        pmu_params->threads_meta_set[i].tid = NULL;
    }
}

static int etmemd_start_sample_thread(struct pmu_params *pmu_params, int cpu_set_count, int cpu_set_size,
                                      struct perf_cpu_monitor **perf_cpu_monitors)
{
    int i;
    int ret;
    struct sample_thread_args *thread_args = NULL;

    thread_args = (struct sample_thread_args *)calloc(cpu_set_count, sizeof(struct sample_thread_args));
    if (thread_args == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for thread_args fail\n");
        return -1;
    }

    for (i = 0; i < cpu_set_count; i++) {
        thread_args[i].cpu_set_size = cpu_set_size;
        thread_args[i].cpu_set_index = i;
        thread_args[i].perf_cpu_monitors = perf_cpu_monitors;
        thread_args[i].pmu_params = pmu_params;

        pmu_params->threads_meta_set[i].tid = (pthread_t *)calloc(1, sizeof(pthread_t));
        if (pmu_params->threads_meta_set[i].tid == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc for g_threads_meta_set[%d].tid fail\n", i);
            goto start_thread_out;
        }

        ret = pthread_create(pmu_params->threads_meta_set[i].tid, NULL, pmu_sample_thread, &thread_args[i]);
        if (ret != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "start sample thread for cpu %d - %d fail", \
                i * cpu_set_size, (i + 1) * cpu_set_size - 1);
            free(pmu_params->threads_meta_set[i].tid);
            goto start_thread_out;
        }
    }
    return 0;

start_thread_out:
    pmu_threads_out(pmu_params, cpu_set_count);

    return -1;
}

/* This function starts the sample thread to monitor specified performance events on designated CPU cores.
 * It initializes performance monitoring parameters, allocates memory for thread metadata,
 * and sets up the process address space for monitoring. */
static int etmemd_start_sample_threads(struct pmu_params *pmu_params)
{
    struct perf_cpu_monitor **perf_cpu_monitors = NULL;
    uint64_t *events_code;
    int cpu_set_size = pmu_params->cpu_set_size;
    int cpu_set_count = SYS_CORES / cpu_set_size;
    int ret;
    int pid = pmu_params->pid;

    events_code = (uint64_t *)calloc(EVENT_NUM, sizeof(uint64_t));
    if (events_code == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for events_code fail\n");
        ret = -1;
        return ret;
    }

    ret = perf_process_events_code(events_code);
    if (ret != 0) {
        goto event_out;
    }

    pmu_params->threads_meta_set = (struct sample_thread_meta *)calloc(cpu_set_count,
        sizeof(struct sample_thread_meta));
    if (pmu_params->threads_meta_set == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for g_threads_meta_set fail\n");
        ret = -1;
        goto event_out;
    }

    ret = update_page_refs_from_vma(pmu_params, &(pmu_params->page_refs_head), false);
    if (ret != 0) {
        goto init_vma_out;
    }

    perf_cpu_monitors = init_perf_cpu_monitors(pmu_params->sample_period,
                                               events_code, pid);
    if (perf_cpu_monitors == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "init_perf_cpu_monitors fail\n");
        goto init_monitor_out;
    }

    ret = etmemd_start_sample_thread(pmu_params, cpu_set_count, cpu_set_size, perf_cpu_monitors);
    if (ret != 0) {
        goto thread_out;
    }
    return 0;

thread_out:
    clear_perf_cpu_monitors(perf_cpu_monitors);

init_monitor_out:
    clear_vma_info_list(pmu_params);

init_vma_out:
    free(pmu_params->threads_meta_set);
    pmu_params->threads_meta_set = NULL;

event_out:
    free(events_code);
    return ret;
}

static inline void reset_page_refs_count(struct page_refs **page_refs)
{
    while ((*page_refs)->next != NULL) {
        (*page_refs)->count = 0;
        (*page_refs) = (*page_refs)->next;
    }
}

void merge_page_refs(struct pmu_params *pmu_params, struct page_sort **page_sort, struct memory_grade **memory_grade)
{
    int i;
    int loop = 0;
    struct page_refs *page_refs_start = NULL;
    struct page_refs *page_refs_end = NULL;

    if (page_sort == NULL || memory_grade == NULL || *page_sort == NULL || *memory_grade == NULL) {
        return;
    }

    loop = (*page_sort)->loop;
    for (i = 0; i < loop + 1; i++) {
        if ((*page_sort)->page_refs_sort[i] == NULL) {
            continue;
        }

        if (page_refs_start == NULL) {
            page_refs_start = (*page_sort)->page_refs_sort[i];
            page_refs_end = page_refs_start;
            reset_page_refs_count(&page_refs_end);
        } else {
            page_refs_end->next = (*page_sort)->page_refs_sort[i];
            reset_page_refs_count(&page_refs_end);
        }
    }

    if ((*memory_grade)->hot_pages != NULL) {
        if (page_refs_start == NULL) {
            page_refs_start = (*memory_grade)->hot_pages;
            page_refs_end = page_refs_start;
            reset_page_refs_count(&page_refs_end);
        } else {
            page_refs_end->next = (*memory_grade)->hot_pages;
            reset_page_refs_count(&page_refs_end);
        }
    }

    if ((*memory_grade)->cold_pages != NULL) {
        if (page_refs_start == NULL) {
            page_refs_start = (*memory_grade)->cold_pages;
            page_refs_end = page_refs_start;
            reset_page_refs_count(&page_refs_end);
        } else {
            page_refs_end->next = (*memory_grade)->cold_pages;
            reset_page_refs_count(&page_refs_end);
        }
    }
    (*memory_grade)->cold_pages = NULL;
    (*memory_grade)->hot_pages = NULL;
    page_refs_end->count = 0;
    pmu_params->page_refs_head = page_refs_start;
}

void etmemd_stop_sample(struct pmu_params *pmu_params)
{
    int cpu_set_size = pmu_params->cpu_set_size;
    int cpu_set_count = cpu_set_count = SYS_CORES / cpu_set_size;

    pmu_threads_out(pmu_params, cpu_set_count);
    free(pmu_params->threads_meta_set);
    pmu_params->threads_meta_set = NULL;

    clear_vma_info_list(pmu_params);
    pmu_params->vma_updata_count = 0;
    pmu_params->page_refs_head = NULL;
}

struct page_refs *etmemd_do_sample(struct pmu_params *pmu_params)
{
    int ret;

    if (pmu_params == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "pmu_params struct is null for pid %u\n", pmu_params->pid);
        return NULL;
    }

    if (pmu_params->threads_meta_set == NULL) {
        ret = etmemd_start_sample_threads(pmu_params);
        if (ret != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "start sample thread failed.");
            return NULL;
        }
    }

    pmu_params->vma_updata_count = (pmu_params->vma_updata_count + 1) % \
                                             (pmu_params->vma_updata_rate);
    if (pmu_params->vma_updata_count == 0) {
        ret = update_page_refs_from_vma(pmu_params, &(pmu_params->page_refs_head), true);
        if (ret != 0) {
            return NULL;
        }
    }

    return pmu_params->page_refs_head;
}
#endif