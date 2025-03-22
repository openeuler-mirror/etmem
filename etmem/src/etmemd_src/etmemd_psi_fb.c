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
 * Author: liubo <liubo254@huawei.com>
 * Create: 2023-08-18
 * Description: Etmemd psi fb API.
 ******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <securec.h>
#include <math.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "securec.h"
#include "etmemd_log.h"
#include "etmemd_common.h"
#include "etmemd_file.h"
#include "etmemd_engine.h"
#include "etmemd_psi.h"
#include "etmemd_scan.h"
#include "etmemd_migrate.h"
#include "etmemd_pool_adapter.h"

#define PROC_PRESSURE_MEMORY            "/proc/pressure/memory"
#define SYS_CGROUP_FS                   "/sys/fs/cgroup"
#define CPUACCT                         "/cpuacct"
#define MEMORY                          "/memory"
#define MEMORY_PRESSURE                 "/memory.pressure"
#define SOME_PRESSURE                   "some"
#define FULL_PRESSURE                   "full"
#define MAX_CG_PATH_LEN                 64
#define UPGRADE_THRESHOLD               5
#define DOWNGRADE_THRESHOLD             (-2)
#define FIFTY_PERCENT                   0.5
#define ONE_PERCENT                     0.01
#define RATE_STRIDE                     ONE_PERCENT
#define TEN_PERCENT                     0.1
#define SIZE_1G                         (1UL << 30)
#define max(a, b)                       ((a) > (b) ? (a) : (b))
#define min(a, b)                       ((a) > (b) ? (b) : (a))

#define HASH_ADD_ULLONG(head, ullongfield, add)	\
    HASH_ADD(hh, head, ullongfield, sizeof(unsigned long long), add)
#define HASH_FIND_ULLONG(head, findullong, out)	\
    HASH_FIND(hh, head, findullong, sizeof(unsigned long long), out)

static struct cg_obj *alloc_cg_obj_node(size_t cgroup_path_len, const char *glob_path,
                                        size_t cpuacct_cg_len, double reclaim_rate, ino_t inode);

/* hash operations */
static void add_cg_obj(struct cg_obj **cg_hash, struct cg_obj *cg_obj)
{
    HASH_ADD_ULLONG(*cg_hash, inode_num, cg_obj);
}

static struct cg_obj *find_cg_obj(struct cg_obj **cg_hash, ino_t inode_num)
{
    struct cg_obj *s = NULL;
    HASH_FIND_ULLONG(*cg_hash, &inode_num, s);
    return s;
}

static void delete_cg_obj(struct cg_obj **cg_hash, struct cg_obj *cg_obj)
{
    HASH_DEL(*cg_hash, cg_obj);
    free(cg_obj->path);
    free(cg_obj);
}

static void delete_all(struct cg_obj **cg_hash)
{
    struct cg_obj *curr = NULL;
    struct cg_obj *tmp = NULL;
    HASH_ITER(hh, *cg_hash, curr, tmp) {
        delete_cg_obj(cg_hash, curr);
    }
}

static void update_reclaim_rate(struct cg_obj *p, bool validate,
                                double reclaim_rate_max,
                                double reclaim_rate_min)
{
    p->gather = validate ? max(0, p->gather + 1) : min(0, p->gather -1);
    if (p->gather >= UPGRADE_THRESHOLD) {
        p->reclaim_rate = min(p->reclaim_rate + RATE_STRIDE, reclaim_rate_max);
        p->gather = 0;
        etmemd_log(ETMEMD_LOG_DEBUG, "increase reclaim rate to %f", p->reclaim_rate);
    } else if (p->gather <= DOWNGRADE_THRESHOLD) {
        p->reclaim_rate = max(p->reclaim_rate - RATE_STRIDE, reclaim_rate_min);
        p->gather = 0;
        etmemd_log(ETMEMD_LOG_DEBUG, "decrease reclaim rate to %f", p->reclaim_rate);
    }
    return;
}

static void psi_next_working_params(struct psi_task_params **params)
{
    while (*params != NULL && (*params)->state != STATE_WORKING) {
        *params = (*params)->next;
    }
}

#define psi_factory_foreach_working_pid_params(iter, factory) \
    for ((iter) = (factory)->working_head, psi_next_working_params(&(iter)); \
            (iter) != NULL; \
            (iter) = (iter)->next, psi_next_working_params(&(iter)))

#define psi_factory_foreach_pid_params(iter, factory) \
    for ((iter) = (factory)->working_head; (iter) != NULL; (iter) = (iter)->next)

static void release_task_cg_obj(struct psi_task_params *params)
{
    struct cg_obj *tmp_cg_obj = NULL;

    while (params->cg_list) {
        tmp_cg_obj = params->cg_list->next;
        delete_cg_obj(&params->cg_hash, params->cg_list);
        params->cg_obj_cnt--;
        params->cg_list = tmp_cg_obj;
    }

    params->cg_list = NULL;
    params->cg_obj_cnt = 0;
}

static void free_task_params(struct psi_task_params *params)
{
    delete_all(&params->cg_hash);
    free(params->cg_dir);
    free(params);
}

/*
 * for each dir globed here: if it's new and has never been spotted before,
 * alloc a cg_obj to track it and add it to hash. No need to remove unpresent
 * cg_objs because they will be deleted in psi_do_reclaim
 */
static int psi_update_task_cg(struct psi_task_params *params)
{
    int ret;
    size_t i;
    glob_t buf;
    struct stat fileinfo;
    struct cg_obj *tmp = NULL;

    ret = glob(params->cg_dir, GLOB_NOSORT | GLOB_BRACE | GLOB_ERR | GLOB_ONLYDIR, NULL, &buf);
    if (ret != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "glob get task cgroup failed. %s", params->cg_dir);
        return -1;
    }

    for (i = 0; i < buf.gl_pathc; i++) {
        ret = lstat(buf.gl_pathv[i], &fileinfo);
        if (ret != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "lstat get file info failed. buf: %s", buf.gl_pathv[i]);
            goto err;
        }

        tmp = find_cg_obj(&params->cg_hash, fileinfo.st_ino);
        if (tmp != NULL) {
            tmp->present = true;
            continue;
        }
        tmp = alloc_cg_obj_node(strlen(buf.gl_pathv[i]), buf.gl_pathv[i],
                                strlen(SYS_CGROUP_FS) + strlen(CPUACCT), params->reclaim_rate, fileinfo.st_ino);
        if (tmp == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "allocating cg_obj fail, path: %s", buf.gl_pathv[i]);
            goto err;
        }

        add_cg_obj(&params->cg_hash, tmp);
        tmp->next = params->cg_list;
        params->cg_list = tmp;
        params->cg_obj_cnt++;
    }

    globfree(&buf);
    return 0;
err:
    globfree(&buf);
    release_task_cg_obj(params);
    return -1;
}

/* add and free operations will take effect here */
static void psi_factory_update_pid_params(struct psi_params_factory *factory)
{
    struct psi_task_params **prev = NULL;
    struct psi_task_params *iter = NULL;
    struct psi_task_params *to_add_head = NULL;
    struct psi_task_params *to_add_tail = NULL;

    /* get new added params first */
    pthread_mutex_lock(&factory->mtx);
    to_add_head = factory->to_add_head;
    to_add_tail = factory->to_add_tail;
    factory->to_add_head = NULL;
    factory->to_add_tail = NULL;
    pthread_mutex_unlock(&factory->mtx);

    if (to_add_head != NULL) {
        to_add_tail->next = factory->working_head;
        factory->working_head = to_add_head;
    }

    /* clear the freed params */
    prev = &factory->working_head;
    for (iter = *prev; iter != NULL; iter = *prev) {
        if (iter->state != STATE_FREE) {
            prev = &(iter->next);
            psi_update_task_cg(iter);
            continue;
        }
        *prev = iter->next;
        iter->next = NULL;
        free_task_params(iter);
    }
}

static bool psi_factory_working_empty(struct psi_params_factory *factory)
{
    struct psi_task_params *task_params = NULL;

    psi_factory_foreach_pid_params(task_params, factory) {
        if (task_params->state == STATE_WORKING) {
            return false;
        }
    }
    return true;
}

static bool system_support_psi(void)
{
    char resolve_path[PATH_MAX] = {0};
    struct stat info;
    int r;
    int fd;

    /* check file is accessable */
    if (realpath(PROC_PRESSURE_MEMORY, resolve_path) == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "%s file is not a real path(%s)\n", PROC_PRESSURE_MEMORY, strerror(errno));
        return false;
    }

    fd = open(PROC_PRESSURE_MEMORY, O_RDONLY);
    if (fd == -1) {
        return false;
    }

    r = fstat(fd, &info);
    if (r == -1) {
        (void)close(fd);
        return false;
    }

    if (S_ISDIR(info.st_mode)) {
        (void)close(fd);
        return false;
    }

    (void)close(fd);

    return true;
}

enum psi_pre {
    SOME,
    FULL,
};

static int set_memory_pressure(struct pressure *pressure_str, char *avg_str, char *avg_num)
{
    if (strcmp(avg_str, "avg10") == 0) {
        pressure_str->avg10 = strtof(avg_num, NULL);
    } else if (strcmp(avg_str, "avg60") == 0) {
        pressure_str->avg60 = strtof(avg_num, NULL);
    } else if (strcmp(avg_str, "avg300") == 0) {
        pressure_str->avg300 = strtof(avg_num, NULL);
    } else if (strcmp(avg_str, "total") == 0) {
        get_unsigned_long_value(avg_num, &pressure_str->total);
    } else {
        return -1;
    }

    return 0;
}

static int get_memory_pressure_num(char *getline, struct memory_pressure *mm_pressure, enum psi_pre pre_type)
{
    char *pair = NULL;
    char *saveptr_pre = NULL;
    char *saveptr_avg = NULL;
    char *pDelimiter = " ";
    char *avg_delim = "=";
    char *avg_str = NULL;
    char *avg_num = NULL;
    char *pressure_str = getline + (pre_type == SOME ? strlen(SOME_PRESSURE) :
		                                       strlen(FULL_PRESSURE));
    struct pressure *pressure_msg = (pre_type == SOME ? &mm_pressure->some_pre :
                                                       &mm_pressure->full_pre);

    for (pair = strtok_r(pressure_str, pDelimiter, &saveptr_pre); pair != NULL;
         pair = strtok_r(NULL, pDelimiter, &saveptr_pre)) {
        avg_str = strtok_r(pair, avg_delim, &saveptr_avg);
        if (avg_str == NULL) {
            return -1;
        }

        avg_num = strtok_r(NULL, avg_delim, &saveptr_avg);
        if (avg_num == NULL) {
            return -1;
        }

        if (set_memory_pressure(pressure_msg, avg_str, avg_num) != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "set memory pressure failed.");
            return -1;
        }
    }

    return 0;
}

static int get_memory_pressure_some(const char *cg_pressure_path, struct memory_pressure *mm_pressure)
{
    FILE *file = NULL;
    char get_line[FILE_LINE_MAX_LEN] = {};
    int ret = -1;

    file = fopen(cg_pressure_path, "r");
    if (file == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "fopen %s failed", cg_pressure_path);
        return -1;
    }
    etmemd_log(ETMEMD_LOG_DEBUG, "read psi from %s", cg_pressure_path);

    if (fgets(get_line, FILE_LINE_MAX_LEN - 1, file) != NULL) {
        etmemd_log(ETMEMD_LOG_DEBUG, "psi: %s", get_line);
        if (get_line[strlen(get_line)-1] == '\n') {
            get_line[strlen(get_line)-1] = '\0';
        }
        if (strncmp(get_line, SOME_PRESSURE, strlen(SOME_PRESSURE))) {
            etmemd_log(ETMEMD_LOG_ERR, "get psi some error: %s", get_line);
        }

        if (get_memory_pressure_num(get_line, mm_pressure, SOME) != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "parse psi some num error: %s", get_line);
        } else {
            ret = 0;
        }
    } else {
        etmemd_log(ETMEMD_LOG_ERR, "failed to get PSI from path: %s", cg_pressure_path);
    }

    (void)fclose(file);
    return ret;
}

static int get_cgroup_fd(const char *cg_dir, const char *file_name, int mode)
{
    char *file_path = NULL;
    size_t file_str_size;
    int fd;

    /* for cgroup v1: memory info is stored in /sys/fs/cgroup/memory/name/xx content */
    file_str_size = strlen(SYS_CGROUP_FS) + strlen(MEMORY) + 1 +
                    strlen(cg_dir) + 1 + strlen(file_name) + 1;
    file_path = (char *)calloc(file_str_size, sizeof(char));
    if (file_path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for %s path fail\n", file_name);
        return -1;
    }

    if (snprintf_s(file_path, file_str_size, file_str_size - 1,
                   "%s%s%s%s%s%s", SYS_CGROUP_FS, MEMORY, "/",
                   cg_dir, "/", file_name) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf for get fd %s fail\n", file_name);
        free(file_path);
        return -1;
    }

    fd = open(file_path, mode);
    if (fd == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "open file %s in file_path: %s fail\n", file_path, file_name);
        free(file_path);
        return -1;
    }

    free(file_path);
    return fd;
}

static int read_from_cgroup_file(const char *cg_dir, const char *file_name, unsigned long *value)
{
    int fd;
    ssize_t recv_size;
    char *buf = NULL;
    u_int64_t size = 32;
    int ret = -1;

    fd = get_cgroup_fd(cg_dir, file_name, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    buf = (char *)calloc(size, sizeof(char));
    if (buf == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for buf fail\n");
        goto err_out;
    }

    recv_size = read(fd, buf, size);
    if (recv_size < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read from cgroup:%s file %s fail: %s\n",
            cg_dir, file_name, strerror(errno));
        goto free_buf;
    }

    for (ssize_t i = 0; i < recv_size; i++) {
        if (buf[i] == '\n') {
            buf[i] = '\0';
        }
    }

    if (get_unsigned_long_value(buf, value) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get value with strtoul fail.\n");
        goto free_buf;
    }

    ret = 0;

free_buf:
    free(buf);
err_out:
    (void)close(fd);
    return ret;
}

static int write_cgroup_file(const char *cg_dir, const char *file_name, unsigned long value)
{
    int fd;
    ssize_t res;
    unsigned char *buf = NULL;
    u_int64_t size = 32;
    int ret = -1;

    fd = get_cgroup_fd(cg_dir, file_name, O_WRONLY);
    if (fd == -1) {
        return -1;
    }

    buf = (unsigned char *)calloc(size, sizeof(unsigned char));
    if (buf == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for buf fail\n");
        goto err_out;
    }

    if (snprintf_s(buf, size, size - 1,
                   "%lu", value) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf fail\n");
        goto free_buf;
    }

    res = write(fd, buf, size);
    if (res < 0) {
        etmemd_log(ETMEMD_LOG_ERR, "write cgroup:%s file:%s, try to write: %s, fail: %s\n",
            cg_dir, file_name, buf, strerror(errno));
        goto free_buf;
    }

    ret = 0;

free_buf:
    free(buf);
err_out:
    (void)close(fd);
    return ret;
}

static int read_from_cgroup_vmstat(const char *cg_dir, const char *file_name,
                                   unsigned long *value, const char *cmpstr)
{
    int fd;
    int ret = -1;
    FILE *file = NULL;
    char get_line[FILE_LINE_MAX_LEN] = {};
    char* pkey = NULL;
    char* pvalue = NULL;
    char* pDelimiter = " ";

    fd = get_cgroup_fd(cg_dir, file_name, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    file = fdopen(fd, "r");
    if (file == NULL) {
        return -1;
    }

    while (fgets(get_line, FILE_LINE_MAX_LEN - 1, file) != NULL) {
        if (strstr(get_line, cmpstr) == NULL) {
            continue;
        }

        pkey = strtok_r(get_line, pDelimiter, &pvalue);
        if (pkey == NULL || pvalue == NULL) {
            etmemd_log(ETMEMD_LOG_ERR, "strtok_r fail\n");
            return -1;
        }

        for (size_t i = 0; i < strlen(pvalue); i++) {
            if (pvalue[i] == '\n') {
                pvalue[i] = '\0';
            }
        }

        if (get_unsigned_long_value(pvalue, value) != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "get value with strtoul fail.\n");
            break;
        }

        ret = 0;
        break;
    }

    (void)fclose(file);
    return ret;
}

static bool validate_pressure(const char *cg_pressure_path, double task_pressure)
{
    struct memory_pressure mm_pressure;
    char *mm_pressure_filename = NULL;
    unsigned int file_str_size;

    /* for cgroup v1: pressure is stored in /sys/fs/cgroup/cpuacct/name/memory.pressure content */
    file_str_size = strlen(SYS_CGROUP_FS) + strlen(CPUACCT) + 1 +
                    strlen(cg_pressure_path) + strlen(MEMORY_PRESSURE) + 1;
    mm_pressure_filename = (char *)calloc(file_str_size, sizeof(char));
    if (mm_pressure_filename == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for %s path fail\n", mm_pressure_filename);
        return false;
    }

    if (snprintf_s(mm_pressure_filename, file_str_size, file_str_size - 1,
                   "%s%s%s%s%s", SYS_CGROUP_FS, CPUACCT, "/",
                   cg_pressure_path, MEMORY_PRESSURE) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf for mem pressure %s fail\n", cg_pressure_path);
        free(mm_pressure_filename);
        return false;
    }

    if (get_memory_pressure_some(mm_pressure_filename, &mm_pressure) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get memory pressure form cgroup failed.");
        free(mm_pressure_filename);
        return false;
    }

    free(mm_pressure_filename);
    return max(mm_pressure.some_pre.avg10, mm_pressure.some_pre.avg60) <
           task_pressure;
}

static int get_reclaimable_bytes(const char *cg_dir, unsigned long *reclaimable_bytes)
{
    unsigned long inactive_file = 0;
    unsigned long active_file = 0;
    unsigned long file_size;
    unsigned long inactive_anon = 0;
    unsigned long active_anon = 0;
    unsigned long memsw_limit_opt;
    unsigned long memsw_usage_opt;
    unsigned long anon_size;
    unsigned long swapable;
    unsigned long swapfree;

    if (read_from_cgroup_vmstat(cg_dir, "memory.stat",
                                &inactive_file, "total_inactive_file") != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read from cgroup vmstat failed.");
        return -1;
    }

    if (read_from_cgroup_vmstat(cg_dir, "memory.stat",
                                &active_file, "total_active_file") != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read from cgroup vmstat failed.");
        return -1;
    }

    file_size = inactive_file + active_file;

    if (read_from_cgroup_vmstat(cg_dir, "memory.stat",
                                &inactive_anon, "total_inactive_anon") != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read from cgroup vmstat failed.");
        return -1;
    }

    if (read_from_cgroup_vmstat(cg_dir, "memory.stat",
                                &active_anon, "total_active_anon") != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read from cgroup vmstat failed.");
        return -1;
    }

    if (read_from_cgroup_file(cg_dir, "memory.memsw.limit_in_bytes",
                              &memsw_limit_opt) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read memory.memsw.limit_in_bytes failed.");
        return -1;
    }

    if (read_from_cgroup_file(cg_dir, "memory.memsw.usage_in_bytes",
                              &memsw_usage_opt) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read memory.memsw.usage_in_bytes failed.");
        return -1;
    }

    anon_size = inactive_anon + active_anon;
    swapfree = memsw_limit_opt - memsw_usage_opt;

    swapable = min(anon_size, swapfree);

    *reclaimable_bytes = file_size + swapable;
    return 0;
}

#define LIMIT_HUGE_VALUE  (LONG_MAX/2)
static int get_min_by_ratio(const char *cg_dir, unsigned long *value, double task_limit_min_ratio)
{
    unsigned long memlimit = 0;

    if (read_from_cgroup_file(cg_dir, "memory.limit_in_bytes",
                                &memlimit) != 0) {
        return -1;
    }

    // treat a huge value as unconfigured
    if (memlimit > LIMIT_HUGE_VALUE) {
        *value = 0;
        return 0;
    }

    *value = memlimit * task_limit_min_ratio;
    return 0;
}

static int get_limit_minbytes(const char *cg_dir, unsigned long *value,
                              unsigned long task_limit_min_bytes,
                              double task_limit_min_ratio)
{
    unsigned long memory_usage_in_bytes = 0;
    unsigned long reclaimable_bytes;
    unsigned long unreclaimable_maybe = 0;
    unsigned long limit_min_bytes = 0;
    unsigned long memory_min = 0;
    unsigned long memory_low = 0;
    unsigned long min_for_ratio = 0;

    if (read_from_cgroup_file(cg_dir, "memory.usage_in_bytes",
                              &memory_usage_in_bytes) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "read_from_cgroup_file memory.usage_in_bytes failed.");
        return -1;
    }

    if (get_reclaimable_bytes(cg_dir, &reclaimable_bytes) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get_reclaimable_bytes failed.");
        return -1;
    }

    unreclaimable_maybe = memory_usage_in_bytes > reclaimable_bytes ?
                          (memory_usage_in_bytes - reclaimable_bytes) : 0;
    limit_min_bytes = task_limit_min_bytes + unreclaimable_maybe;

    if (read_from_cgroup_file(cg_dir, "memory.min",
                              &memory_min) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "memory_min failed.");
        return -1;
    }
    limit_min_bytes = max(limit_min_bytes, memory_min);

    if (read_from_cgroup_file(cg_dir, "memory.low",
                              &memory_low) != 0) {
        return -1;
    }
    limit_min_bytes = max(limit_min_bytes, memory_low);

    if (get_min_by_ratio(cg_dir, &min_for_ratio, task_limit_min_ratio) != 0) {
        return -1;
    }
    limit_min_bytes = max(limit_min_bytes, min_for_ratio);

    etmemd_log(ETMEMD_LOG_DEBUG,
                "limit_min_bytes: %lu (unreclaim:%lu min:%lu low:%lu min_ratio:%lu)",
                limit_min_bytes, unreclaimable_maybe, memory_min, memory_low, min_for_ratio);
    *value = limit_min_bytes;
    return 0;
}

static int reclaim_by_memory_claim(const char *cg_dir, unsigned long reclaim_size)
{
    if (write_cgroup_file(cg_dir, "memory.reclaim", reclaim_size) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "memory reclaim failed.");
        return -1;
    }

    return 0;
}

static int psi_cg_reclaim(struct cg_obj *curr, struct psi_task_params *task_params,
                          unsigned long *limit_min_bytes_opt, unsigned long *current_mem)
{
    unsigned long reclaim_size;
    /* check the pressure is high or not */
    if (!validate_pressure(curr->path, task_params->pressure)) {
        update_reclaim_rate(curr, false,
                            task_params->reclaim_rate_max,
                            task_params->reclaim_rate_min);
        etmemd_log(ETMEMD_LOG_DEBUG, "memory pressure is high, should not reclaim");
        return 0;
    }

    /* get the limit min bytes should leave in memory */
    if (get_limit_minbytes(curr->path, limit_min_bytes_opt,
                           task_params->limit_min_bytes,
                           task_params->limit_min_ratio) != 0) {
        return -1;
    }

    if (read_from_cgroup_file(curr->path, "memory.usage_in_bytes",
                              current_mem) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "get current_mem failed.");
        return -1;
    }

    etmemd_log(ETMEMD_LOG_DEBUG, "current mem: %lu limit: %lu", current_mem, limit_min_bytes_opt);
    if (current_mem <= limit_min_bytes_opt) {
        etmemd_log(ETMEMD_LOG_DEBUG, "current memory is below the limit min bytes, no need to swap.");
        return 0;
    }

    reclaim_size = (unsigned long)(current_mem - limit_min_bytes_opt) * task_params->reclaim_rate;
    reclaim_size = min(reclaim_size, task_params->reclaim_max_bytes);
    reclaim_size &= ~0xFFF;

    etmemd_log(ETMEMD_LOG_DEBUG,
               "cg_dir: %s should reclaim size: %lu, current: %lu, limit: %lu, reclaim_rate: %.2f",
               curr->path, reclaim_size, current_mem,
               limit_min_bytes_opt, task_params->reclaim_rate);

    if (reclaim_size == 0) {
        return 0;
    }
    /* do reclaim */
    if (reclaim_by_memory_claim(curr->path, reclaim_size) != 0) {
        return -1;
    }
    update_reclaim_rate(curr, true,
                        task_params->reclaim_rate_max,
                        task_params->reclaim_rate_min);
    return 0;
}

static int psi_do_reclaim(struct psi_task_params *task_params)
{
    unsigned long limit_min_bytes_opt = 0;
    unsigned long current_mem = 0;
    struct cg_obj dummy;
    struct cg_obj *curr = NULL;
    struct cg_obj *prev = NULL;

    prev = &dummy;
    prev->next = task_params->cg_list;
    curr = task_params->cg_list;
    etmemd_log(ETMEMD_LOG_DEBUG, "%lu cgroups are recognized in %s",
               task_params->cg_obj_cnt, task_params->cg_dir);
    while (prev->next != NULL) {
        curr = prev->next;
        etmemd_log(ETMEMD_LOG_DEBUG, "cg_dir: %s", curr->path);
        /* if the cg_obj is not present, delete it */
        if (!curr->present) {
            prev->next = curr->next;
            delete_cg_obj(&task_params->cg_hash, curr);
            task_params->cg_obj_cnt--;
            continue;
        }
        curr->present = false;
        if (psi_cg_reclaim(curr, task_params, &limit_min_bytes_opt, &current_mem) != 0) {
            task_params->cg_list = dummy.next;
            return -1;
        }
        prev = curr;
    }
    task_params->cg_list = dummy.next;
    return 0;
}

static int psi_run(struct psi_eng_params *eng_params)
{
    struct psi_task_params *iter = NULL;

    psi_factory_foreach_working_pid_params(iter, &eng_params->factory) {
        if (psi_do_reclaim(iter) != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "psi do reclaim fail\n");
            return -1;
        }
    }

    return 0;
}

static void *psi_main(void *arg)
{
    struct psi_eng_params *eng_params = (struct psi_eng_params *)arg;
    // only invalid pthread id or deatch more than once will cause error
    // so no need to check return value of pthread_detach
    (void)pthread_detach(pthread_self());

    while (true) {
        psi_factory_update_pid_params(&eng_params->factory);
        if (eng_params->finish) {
            etmemd_log(ETMEMD_LOG_DEBUG, "psi task is stopping...\n");
            break;
        }

        if (psi_factory_working_empty(&eng_params->factory)) {
            goto next;
        }

        if (psi_run(eng_params) != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "psi run fail.");
            goto next;
        }

next:
        sleep(eng_params->interval);
    }

    psi_factory_update_pid_params(&eng_params->factory);
    pthread_mutex_destroy(&eng_params->factory.mtx);
    free(eng_params);
    return NULL;
}

static int psi_fill_eng(GKeyFile *config, struct engine *eng)
{
    struct psi_eng_params *params = NULL;
    struct psi_scan *psi_scan = (struct psi_scan *)eng->proj->scan_param;

    if (!system_support_psi()) {
        etmemd_log(ETMEMD_LOG_ERR, "the system is not support psi.");
        return -1;
    }

    params = calloc(1, sizeof(struct psi_eng_params));
    if (params == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "alloc psi engine params fail\n");
        return -1;
    }

    params->interval = psi_scan->interval;
    pthread_mutex_init(&params->factory.mtx, NULL);
    eng->params = params;
    if (pthread_create(&params->worker, NULL, psi_main, params) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "start psi_main worker fail\n");
        goto free_eng_params;
    }

    return 0;

free_eng_params:
    pthread_mutex_destroy(&params->factory.mtx);
    free(params);
    return -1;
}

static void psi_clear_eng(struct engine *eng)
{
    struct psi_eng_params *eng_params = eng->params;
    /* clear psi engine params in psi main */
    eng_params->finish = true;
    eng->params = NULL;
}


static void psi_clear_task(struct task *tk)
{
    struct psi_task_params *params = (struct psi_task_params *)(tk->params);

    // Pid not started i.e not used. Free it here
    if (params->state == STATE_NONE) {
        free_task_params(params);
        return;
    }

    // Pid in use, free by cslide main when call factory_update_pid_params
    // Avoid data race
    params->state = STATE_FREE;

    tk->params = NULL;
}

#define DEFINE_FILL_PARAM_DOUBLE(name)                                   \
static inline int fill_psi_param_##name(void *obj, void *val)                \
{                                                                            \
    struct psi_task_params *params = (struct psi_task_params *)obj;          \
    double value = *(double *)val;                                           \
    if (value <= 0) {                                                        \
        etmemd_log(ETMEMD_LOG_ERR, "PSI fb param: %s: %f invalid!\n", #name, value); \
        return -1;                                                           \
    }                                                                        \
    params->name = value;                                                    \
    etmemd_log(ETMEMD_LOG_DEBUG, "PSI fb param: %s: %f\n", #name, value);    \
    return 0;                                                                \
}

DEFINE_FILL_PARAM_DOUBLE(pressure);
DEFINE_FILL_PARAM_DOUBLE(reclaim_rate);
DEFINE_FILL_PARAM_DOUBLE(reclaim_rate_max);
DEFINE_FILL_PARAM_DOUBLE(reclaim_rate_min);
DEFINE_FILL_PARAM_DOUBLE(limit_min_ratio);

static int check_cgroup_fs_path_valid(char *cgroup_task_path, const char *cg_dir,
                                      unsigned int file_str_size, const char *cg_name)
{
    char resolve_path[PATH_MAX] = {0};

    if (snprintf_s(cgroup_task_path, file_str_size, file_str_size - 1,
                   "%s%s%s%s", SYS_CGROUP_FS, cg_name, "/",
                   cg_dir) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf for %s/%s fail\n", cg_name, cg_dir);
        return -1;
    }

    /* check file is accessable */
    if (realpath(cgroup_task_path, resolve_path) == NULL) {
        etmemd_log(ETMEMD_LOG_ERR,
                   "check cgroup validness fail: %s file is not a real path(%s)\n",
                   cgroup_task_path,
                   strerror(errno));
        return -1;
    }

    return 0;
}

static int check_cgroup_fs_path(const char *cg_dir)
{
    unsigned int file_str_size;
    char *cgroup_task_path = NULL;
    int ret = -1;

    /* check the /sys/fs/cgroup/cpuacct/name and memory is available */
    file_str_size = strlen(SYS_CGROUP_FS) + strlen(CPUACCT) + 1 +
                    strlen(cg_dir) + 1;

    cgroup_task_path = (char *)calloc(file_str_size, sizeof(char));
    if (cgroup_task_path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for %s path fail\n", cg_dir);
        return -1;
    }

    if (check_cgroup_fs_path_valid(cgroup_task_path, cg_dir,
                                   file_str_size, CPUACCT) != 0) {
        goto out;
    }

    if (memset_s(cgroup_task_path, file_str_size, 0, file_str_size) != EOK) {
        etmemd_log(ETMEMD_LOG_ERR, "memset_s for cgroup_task_path fail\n", cg_dir);
        goto out;
    }

    if (check_cgroup_fs_path_valid(cgroup_task_path, cg_dir,
                                   file_str_size, MEMORY) != 0) {
        goto out;
    }

    ret = 0;
out:
    free(cgroup_task_path);
    return ret;
}

static struct cg_obj *alloc_cg_obj_node(size_t cgroup_path_len, const char *glob_path,
                                        size_t cpuacct_cg_len, double reclaim_rate, ino_t inode)
{
    struct cg_obj *task_cg_obj = (struct cg_obj *)calloc(1, sizeof(struct cg_obj));
    if (task_cg_obj == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "calloc for psi cg path node failed.");
        return NULL;
    }

    if (cgroup_path_len == 0 || cgroup_path_len <= cpuacct_cg_len) {
        etmemd_log(ETMEMD_LOG_ERR, "get cgroup path wrong. path: %s", glob_path);
        free(task_cg_obj);
        return NULL;
    }

    task_cg_obj->path = (char *)calloc(cgroup_path_len, sizeof(char));
    if (task_cg_obj->path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "calloc for task cg path failed.");
        free(task_cg_obj);
        return NULL;
    }
    /* +1 here is for '/' */
    if (memcpy_s(task_cg_obj->path, cgroup_path_len,
                 glob_path + cpuacct_cg_len + 1,
                 cgroup_path_len - cpuacct_cg_len) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "memcpy for cg path failed.");
        goto err;
    }

    if (check_cgroup_fs_path(task_cg_obj->path) != 0) {
        goto err;
    }

    task_cg_obj->reclaim_rate = reclaim_rate;
    task_cg_obj->present = true;
    task_cg_obj->inode_num = inode;
    return task_cg_obj;

err:
    free(task_cg_obj->path);
    free(task_cg_obj);
    return NULL;
}

/* cgroup objects will not be recorded immediately here at the init phase */
static int fill_psi_param_cg_dir(void *obj, void *val)
{
    char *cg_dir = (char *)val;
    struct psi_task_params *params = (struct psi_task_params *)obj;
    unsigned int file_str_size;
    char *cgroup_task_path = NULL;

    if (cg_dir == NULL ||
        strlen(cg_dir) <= 0 ||
        strlen(cg_dir) >= MAX_CG_PATH_LEN) {
        etmemd_log(ETMEMD_LOG_ERR, "PSI cg_dir is invalid.\n");
        free(val);
        return -1;
    }

    /* check the /sys/fs/cgroup/cpuacct/name and memory is available */
    file_str_size = strlen(SYS_CGROUP_FS) + strlen(CPUACCT) + 1 +
                    strlen(cg_dir) + 1;
 
    cgroup_task_path = (char *)calloc(file_str_size, sizeof(char));
    if (cgroup_task_path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "malloc for %s path fail\n", cg_dir);
        return -1;
    }

    if (snprintf_s(cgroup_task_path, file_str_size, file_str_size - 1,
                   "%s%s%s%s", SYS_CGROUP_FS, CPUACCT, "/",
                   cg_dir) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "snprintf for %s fail\n", cg_dir);
        goto err_out;
    }

    params->cg_dir = cgroup_task_path;

    return 0;

err_out:
    free(cgroup_task_path);
    free(val);
    return -1;
}

#define DEFINE_FILL_PARAM_STR_TO_UL(name)                                \
static inline int fill_psi_param_##name(void *obj, void *val)                \
{                                                                            \
    unsigned long value;                                                     \
    struct psi_task_params *params = (struct psi_task_params *)obj;          \
    if (get_unsigned_long_value(val, &value) != 0) {                         \
        etmemd_log(ETMEMD_LOG_ERR, "PSI fb param: %s: %s invalid!\n", #name, val); \
        return -1;                                                           \
    }                                                                        \
    params->name = value;                                                    \
    etmemd_log(ETMEMD_LOG_DEBUG, "PSI fb param: %s: %lu\n", #name, value);   \
    free(val);                                                               \
    return 0;                                                                \
}

DEFINE_FILL_PARAM_STR_TO_UL(limit_min_bytes);
DEFINE_FILL_PARAM_STR_TO_UL(reclaim_max_bytes);

static struct config_item g_psi_task_config_items[] = {
    {"pressure", DOUBLE_VAL, fill_psi_param_pressure, true},
    {"reclaim_rate", DOUBLE_VAL, fill_psi_param_reclaim_rate, true},
    {"reclaim_rate_max", DOUBLE_VAL, fill_psi_param_reclaim_rate_max, true},
    {"reclaim_rate_min", DOUBLE_VAL, fill_psi_param_reclaim_rate_min, true},
    {"limit_min_bytes", STR_VAL, fill_psi_param_limit_min_bytes, true},
    {"limit_min_ratio", DOUBLE_VAL, fill_psi_param_limit_min_ratio, true},
    {"reclaim_max_bytes", STR_VAL, fill_psi_param_reclaim_max_bytes, true},
    {"cg_dir", STR_VAL, fill_psi_param_cg_dir, false},
};

static int psi_fill_task(GKeyFile *config, struct task *tk)
{
    struct psi_task_params *params = calloc(1, sizeof(struct psi_task_params));
    if (params == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "alloc psi_task_params param fail\n");
        return -1;
    }

    params->cg_hash = NULL;
    /* set the default pressure value : 0.1 */
    params->pressure = 0.1;

    /* set reclaim rate 0.05, reclaim 5 / 100 size of reclaimable size */
    params->reclaim_rate = 0.05;
    params->reclaim_rate_max = FIFTY_PERCENT;
    params->reclaim_rate_min = ONE_PERCENT;
    params->gather = 0;
    params->limit_min_ratio = TEN_PERCENT;
    params->reclaim_max_bytes = SIZE_1G;

    if (parse_file_config(config, TASK_GROUP,
                          g_psi_task_config_items,
                          ARRAY_SIZE(g_psi_task_config_items),
                          (void *)params) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "psi fill task fail\n");
        goto free_params;
    }

    tk->params = params;
    return 0;

free_params:
    free(params);
    return -1;
}

static void psi_factory_add_pid_params(struct psi_params_factory *factory, struct psi_task_params *params)
{
    enum pid_param_state state = params->state;
    params->state = STATE_WORKING;

    if (state == STATE_NONE) {
        pthread_mutex_lock(&factory->mtx);
        params->next = factory->to_add_head;
        factory->to_add_head = params;
        if (factory->to_add_tail == NULL) {
            factory->to_add_tail = params;
        }
        pthread_mutex_unlock(&factory->mtx);
    }
}

static void psi_factory_remove_pid_params(struct psi_params_factory *factory, struct psi_task_params *params)
{
    params->state = STATE_REMOVE;
}


static int psi_start_task(struct engine *eng, struct task *tk)
{
    struct psi_eng_params *eng_params = (struct psi_eng_params *)eng->params;
    psi_factory_add_pid_params(&eng_params->factory, tk->params);

    return 0;
}

static void psi_stop_task(struct engine *eng, struct task *tk)
{
    struct psi_eng_params *eng_params = (struct psi_eng_params *)eng->params;

    psi_factory_remove_pid_params(&eng_params->factory, tk->params);
}

struct engine_ops g_psi_fb_eng_ops = {
    .fill_eng_params = psi_fill_eng,
    .clear_eng_params = psi_clear_eng,
    .fill_task_params = psi_fill_task,
    .clear_task_params = psi_clear_task,
    .start_task = psi_start_task,
    .stop_task = psi_stop_task,
    .alloc_pid_params = NULL,
    .free_pid_params = NULL,
    .eng_mgt_func = NULL,
};

int fill_engine_type_psi_fb(struct engine *eng, GKeyFile *config)
{
    eng->ops = &g_psi_fb_eng_ops;
    eng->engine_type = PSI_FB_ENGINE;
    eng->name = "psi";
    return 0;
}
