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
 * Description: Etmemd slide API.
 ******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>

#include "securec.h"
#include "etmemd_log.h"
#include "etmemd_common.h"
#include "etmemd_engine.h"
#include "etmemd_slide.h"
#include "etmemd_scan.h"
#include "etmemd_migrate.h"
#include "etmemd_pool_adapter.h"
#include "etmemd_file.h"

static struct memory_grade *slide_policy_interface(struct page_sort **page_sort, const struct task_pid *tpid)
{
    struct slide_params *slide_params = (struct slide_params *)(tpid->tk->params);
    struct page_refs **page_refs = NULL;
    struct memory_grade *memory_grade = NULL;
    unsigned long need_2_swap_num;
    volatile uint64_t count = 0;
    struct page_scan *page_scan = (struct page_scan *)tpid->tk->eng->proj->scan_param;

    if (slide_params == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "cannot get params for slide\n");
        return NULL;
    }

    memory_grade = (struct memory_grade *)calloc(1, sizeof(struct memory_grade));
    if (memory_grade == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for memory grade fail\n");
        return NULL;
    }

    if (slide_params->dram_percent == 0) {
        page_refs = (*page_sort)->page_refs;

        while (*page_refs != NULL) {
            if ((*page_refs)->count >= slide_params->t) {
                *page_refs = add_page_refs_into_memory_grade(*page_refs, &memory_grade->hot_pages);
                continue;
            }
            *page_refs = add_page_refs_into_memory_grade(*page_refs, &memory_grade->cold_pages);
        }

        return memory_grade;
    }

    need_2_swap_num = check_should_migrate(tpid);
    if (need_2_swap_num == 0)
        goto count_out;

    for (int i = 0; i < page_scan->loop + 1; i++) {
        page_refs = &((*page_sort)->page_refs_sort[i]);

        while (*page_refs != NULL) {
            if ((*page_refs)->count >= slide_params->t) {
                *page_refs = add_page_refs_into_memory_grade(*page_refs, &memory_grade->hot_pages);
                goto count_out;
            }

            *page_refs = add_page_refs_into_memory_grade(*page_refs, &memory_grade->cold_pages);
            count++;
            if (count >= need_2_swap_num)
                goto count_out;
        }
    }

count_out:
    return memory_grade;
}

static int slide_do_migrate(unsigned int pid, const struct memory_grade *memory_grade)
{
    int ret;
    char pid_str[PID_STR_MAX_LEN] = {0};

    if (memory_grade == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "memory grade for slide should not be NULL for pid %u\n", pid);
        return -1;
    }

    if (snprintf_s(pid_str, PID_STR_MAX_LEN, PID_STR_MAX_LEN - 1, "%u", pid) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf pid fail %u", pid);
        return -1;
    }

    /* we swap the cold pages for temporary, and do other operations later */
    ret = etmemd_grade_migrate(pid_str, memory_grade);
    return ret;
}

static int check_sysmem_lower_threshold(struct task_pid *tk_pid)
{
    unsigned long mem_total;
    unsigned long mem_free;
    int vm_cmp;
    int ret;

    ret = get_mem_from_proc_file(NULL, PROC_MEMINFO, &mem_total, "MemTotal");
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get memtotal fail\n");
        return DONT_SWAP;
    }

    ret = get_mem_from_proc_file(NULL, PROC_MEMINFO, &mem_free, "MemFree");
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get memfree fail\n");
        return DONT_SWAP;
    }

    /* Calculate the free memory percentage in 0 - 100 */
    vm_cmp = (mem_free * 100) / mem_total;
    if (vm_cmp < tk_pid->tk->eng->proj->sysmem_threshold) {
        return DO_SWAP;
    }

    return DONT_SWAP;
}

static int check_pid_should_swap(const char *pid, unsigned long vmrss, const struct task_pid *tk_pid)
{
    unsigned long vmswap;
    unsigned long vmcmp;
    int ret;

    ret = get_mem_from_proc_file(pid, STATUS_FILE, &vmswap, "VmSwap");
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get VmSwap fail\n");
        return DONT_SWAP;
    }

    /* Calculate the total amount of memory that can be swappout for the current process
     * and check whether the memory is larger than the current swapout amount.
     * If true, continue swap-out; otherwise, abort the swap-out process. */
    vmcmp = (vmrss + vmswap) / 100 * tk_pid->tk->eng->proj->sysmem_threshold;
    if (vmcmp > vmswap) {
        return DO_SWAP;
    }

    return DONT_SWAP;
}

static int check_pidmem_lower_threshold(struct task_pid *tk_pid)
{
    struct slide_params *params = NULL;
    unsigned long vmrss;
    int ret;
    char pid_str[PID_STR_MAX_LEN] = {0};

    params = (struct slide_params *)tk_pid->tk->params;
    if (params == NULL) {
        return DONT_SWAP;
    }

    if (snprintf_s(pid_str, PID_STR_MAX_LEN, PID_STR_MAX_LEN - 1, "%u", tk_pid->pid) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf pid fail %u", tk_pid->pid);
        return DONT_SWAP;
    }

    ret = get_mem_from_proc_file(pid_str, STATUS_FILE, &vmrss, "VmRSS");
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get VmRSS fail\n");
        return DONT_SWAP;
    }

    if (params->swap_threshold == 0) {
        return check_pid_should_swap(pid_str, vmrss, tk_pid);
    }

    if (vmrss > params->swap_threshold) {
        return DO_SWAP;
    }

    return DONT_SWAP;
}

static int check_should_swap(struct task_pid *tk_pid)
{
    if (tk_pid->tk->eng->proj->sysmem_threshold == -1) {
        return DO_SWAP;
    }

    if (check_sysmem_lower_threshold(tk_pid) == DONT_SWAP) {
        return DONT_SWAP;
    }

    return check_pidmem_lower_threshold(tk_pid);
}

#ifdef ENABLE_PMU
static struct page_refs *handle_page_refs(struct task_pid *tk_pid, struct task *task_ptr)
{
    struct slide_params *slide = (struct slide_params *)task_ptr->params;
    struct page_refs *page_refs = NULL;
    if (slide->pmu_params == NULL) {
        page_refs = etmemd_do_scan(tk_pid, task_ptr);
    } else {
        slide->pmu_params->pid = tk_pid->pid;
        slide->pmu_params->swap_flag = task_ptr->swap_flag;
        page_refs = etmemd_do_sample(slide->pmu_params);
    }
    return page_refs;
}
#else
static struct page_refs *handle_page_refs(struct task_pid *tk_pid, struct task *task_ptr)
{
    return etmemd_do_scan(tk_pid, task_ptr);
}
#endif


static void *slide_executor(void *arg)
{
    struct task_pid *tk_pid = (struct task_pid *)arg;
    struct page_refs *page_refs = NULL;
    struct memory_grade *memory_grade = NULL;
    struct page_sort *page_sort = NULL;
    struct task *task_ptr = (struct task *)tk_pid->tk;

    /* The pthread_setcancelstate interface returns an error only when the
     * input parameter state is invalid, no need to check return value.
     */
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    /* register cleanup function in case of unexpected cancellation detected */
    pthread_cleanup_push(clean_page_refs_unexpected, &page_refs);

    if (check_should_swap(tk_pid) == DONT_SWAP) {
        goto scan_out;
    }

    page_refs = handle_page_refs(tk_pid, task_ptr);
    if (page_refs == NULL) {
        etmemd_log(ETMEMD_LOG_WARN, "pid %u cannot get page refs\n", tk_pid->pid);
        goto scan_out;
    }

    page_sort = sort_page_refs(&page_refs, tk_pid);
    if (page_sort == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "failed to alloc memory for page sort.", tk_pid->pid);
        goto scan_out;
    }

    memory_grade = slide_policy_interface(&page_sort, tk_pid);

scan_out:
#ifndef ENABLE_PMU
    clean_page_sort_unexpected(&page_sort);
#endif

    pthread_cleanup_pop(1);

    if (memory_grade == NULL) {
        etmemd_log(ETMEMD_LOG_DEBUG, "pid %u memory grade is empty\n", tk_pid->pid);
        goto exit;
    }

    if (slide_do_migrate(tk_pid->pid, memory_grade) != 0) {
        etmemd_log(ETMEMD_LOG_DEBUG, "slide migrate for pid %u fail\n", tk_pid->pid);
    }

    if (etmemd_reclaim_swapcache(tk_pid) != 0) {
        etmemd_log(ETMEMD_LOG_DEBUG, "etmemd_reclaim_swapcache pid %u fail\n", tk_pid->pid);
    }

exit:
#ifdef ENABLE_PMU
    if (((struct slide_params *)task_ptr->params)->pmu_params != NULL) {
        merge_page_refs(((struct slide_params *)task_ptr->params)->pmu_params,
            &page_sort, &memory_grade);
    }
#endif
    clean_memory_grade_unexpected(&memory_grade);

    if (malloc_trim(0) == 0) {
        etmemd_log(ETMEMD_LOG_INFO, "malloc_trim to release memory for pid %u fail\n", tk_pid->pid);
    }

    (void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();

    return NULL;
}

static int fill_task_threshold(void *obj, void *val)
{
    struct slide_params *params = (struct slide_params *)obj;
    int t = parse_to_int(val);

    if (t < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "slide engine param T should not be less than 0");
        return -1;
    }

    params->t = t;
    return 0;
}

static int fill_task_dram_percent(void *obj, void *val)
{
    struct slide_params *params = (struct slide_params *)obj;
    int value = parse_to_int(val);

    if (value <= 0 || value > 100) {
        etmemd_log(ETMEMD_LOG_WARN,
                    "dram_percent %d is abnormal, the reasonable range is (0, 100],\
                        cancle the dram_percent parameter of current task\n", value);
        value = 0;
    }

    params->dram_percent = value;

    return 0;
}

static int fill_task_swap_threshold(void *obj, void *val)
{
    struct slide_params *params = (struct slide_params *)obj;
    char *swap_threshold_string = (char *)val;
    unsigned long swap_threshold;

    if (get_swap_threshold_inKB(swap_threshold_string, &swap_threshold) != 0) {
        etmemd_log(ETMEMD_LOG_WARN,
                   "parse swap_threshold failed.\n");
        free(swap_threshold_string);
        return -1;
    }
   
    free(swap_threshold_string);
    params->swap_threshold = swap_threshold;

    return 0;
}

#ifdef ENABLE_PMU
static int fill_task_sample_period(void *obj, void *val)
{
    struct slide_params *params = (struct slide_params *)obj;
    unsigned value = parse_to_int(val);
    if (value <= 0) {
        etmemd_log(ETMEMD_LOG_WARN,
                   "sample_period %d is abnormal, [1000,10000] is recommanded!\n", value);
        return -1;
    }

    if (params->pmu_params == NULL) {
        params->pmu_params = calloc(1, sizeof(struct pmu_params));
        if (params->pmu_params == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc for pmu_params failed.\n");
            return -1;
        }
    }
    params->pmu_params->sample_period = value;

    return 0;
}

static int fill_task_vma_updata_rate(void *obj, void *val)
{
    struct slide_params *params = (struct slide_params *)obj;
    int value = parse_to_int(val);
    if (value <= 0) {
        etmemd_log(ETMEMD_LOG_WARN,
                   "vma_updata_rate is abnormal, the reasonable value should bigger than 1!\n");
        value = 1;
    }

    if (params->pmu_params == NULL) {
        params->pmu_params = calloc(1, sizeof(struct pmu_params));
        if (params->pmu_params == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc for pmu_params failed.\n");
            return -1;
        }
    }
    params->pmu_params->vma_updata_rate = value;
    params->pmu_params->vma_updata_count = 0;

    return 0;
}

static int fill_task_cpu_set_size(void *obj, void *val)
{
    struct slide_params *params = (struct slide_params *)obj;
    int value = parse_to_int(val);
    int ret;
    if (value <= 0) {
        etmemd_log(ETMEMD_LOG_WARN,
                   "cpu_set_size is abnormal, the reasonable value should bigger than 1 !\n");
        value = 1;
    }

    if (params->pmu_params == NULL) {
        params->pmu_params = calloc(1, sizeof(struct pmu_params));
        if (params->pmu_params == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "malloc for pmu_params failed.\n");
            return -1;
        }
    }
    params->pmu_params->cpu_set_size = value;
    ret = pthread_mutex_init(&(params->pmu_params->vma_list_mutex), NULL);
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "init vma_list_mutex failed.\n");
        return -1;
    }

    return 0;
}
#endif

static struct config_item g_slide_task_config_items[] = {
    {"T", INT_VAL, fill_task_threshold, false},
    {"swap_threshold", STR_VAL, fill_task_swap_threshold, true},
    {"dram_percent", INT_VAL, fill_task_dram_percent, true},
#ifdef ENABLE_PMU
    {"sample_period", INT_VAL, fill_task_sample_period, true},
    {"vma_updata_rate", INT_VAL, fill_task_vma_updata_rate, true},
    {"cpu_set_size", INT_VAL, fill_task_cpu_set_size, true},
#endif
};

static int slide_fill_task(GKeyFile *config, struct task *tk)
{
    struct slide_params *params = calloc(1, sizeof(struct slide_params));
    struct page_scan *page_scan = (struct page_scan *)tk->eng->proj->scan_param;

    if (params == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "alloc slide param fail\n");
        return -1;
    }

    if (parse_file_config(config, TASK_GROUP, g_slide_task_config_items, ARRAY_SIZE(g_slide_task_config_items),
                          (void *)params) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "slide fill task fail\n");
        goto free_params;
    }

    if (params->t > page_scan->loop * WRITE_TYPE_WEIGHT) {
        etmemd_log(ETMEMD_LOG_ERR, "engine param T must less than loop.\n");
        goto free_params;
    }
    tk->params = params;
    return 0;

free_params:
    free(params);
    return -1;
}

static void slide_clear_task(struct task *tk)
{
    etmemd_free_task_pids(tk);
    free(tk->params);
    tk->params = NULL;
}

static int slide_start_task(struct engine *eng, struct task *tk)
{
    struct slide_params *params = tk->params;

    params->executor = malloc(sizeof(struct task_executor));
    if (params->executor == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "slide alloc memory for task_executor fail\n");
        return -1;
    }

    params->executor->tk = tk;
    params->executor->func = slide_executor;
    if (start_threadpool_work(params->executor) != 0) {
        free(params->executor);
        params->executor = NULL;
        etmemd_log(ETMEMD_LOG_ERR, "slide start task executor fail\n");
        return -1;
    }

    return 0;
}

static void slide_stop_task(struct engine *eng, struct task *tk)
{
    struct slide_params *params = tk->params;

#ifdef ENABLE_PMU
    if (params->pmu_params != NULL) {
        etmemd_stop_sample(params->pmu_params);
    }
#endif

    stop_and_delete_threadpool_work(tk);
    etmemd_free_task_pids(tk);
    free(params->executor);
    params->executor = NULL;
}

struct engine_ops g_slide_eng_ops = {
    .fill_eng_params = NULL,
    .clear_eng_params = NULL,
    .fill_task_params = slide_fill_task,
    .clear_task_params = slide_clear_task,
    .start_task = slide_start_task,
    .stop_task = slide_stop_task,
    .alloc_pid_params = NULL,
    .free_pid_params = NULL,
    .eng_mgt_func = NULL,
};

int fill_engine_type_slide(struct engine *eng, GKeyFile *config)
{
    eng->ops = &g_slide_eng_ops;
    eng->engine_type = SLIDE_ENGINE;
    eng->name = "slide";
    return 0;
}
