/******************************************************************************
 * Copyright (c) 2024 KylinSoft Corporation. All rights reserved.
 * etmem is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Enze Li <lienze@kylinos.cn>
 * Create: 2024-08-21
 * Description: Damon engine with SYSFS support.
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "securec.h"
#include "etmemd_log.h"
#include "etmemd_common.h"
#include "etmemd_file.h"
#include "etmemd_engine.h"
#include "etmemd_task.h"
#include "etmemd_task_exp.h"
#include "etmemd_scan.h"
#include "etmemd_damon.h"

#define ON_LEN         2
#define OFF_LEN        3
#define INT_MAX_LEN    10
#define NUM_OF_ATTRS   5
#define NUM_OF_SCHEMES 7

#define DAMON_SYSFS_KDAMONDS_DIR "/sys/kernel/mm/damon/admin/kdamonds"

#define DAMON_SYSFS_PATH_SIZE 128
#define DAMON_PID_STR_MAX_LEN 12

enum damos_action {
    DAMOS_WILLNEED,
    DAMOS_COLD,
    DAMOS_PAGEOUT,
    DAMOS_HUGEPAGE,
    DAMOS_NOHUGEPAGE,
    DAMOS_STAT,
};

struct action_item {
    char *action_str;
    enum damos_action action_type;
};

struct damon_eng_params {
    unsigned long min_sz_region;
    unsigned long max_sz_region;
    unsigned int min_nr_accesses;
    unsigned int max_nr_accesses;
    unsigned int min_age_region;
    unsigned int max_age_region;
    enum damos_action action;
    char *action_str;
};

struct damon_idx {
    unsigned long kdamond_idx;
    unsigned long context_idx;
    unsigned long scheme_idx;
    unsigned long target_idx;
};

enum damon_param {
    DAMON_PARAM_PID_TARGETS,
    DAMON_PARAM_ATTRS,
    DAMON_PARAM_SCHEMES,
    DAMON_PARAM_STATE,
    DAMON_PARAM_NR,
    DAMON_PARAM_NONE,
};

enum damon_attrs {
    DAMON_MONITORING_INTERVALS_SAMPLE,
    DAMON_MONITORING_INTERVALS_AGGR,
    DAMON_MONITORING_INTERVALS_UPDATE,
    DAMON_MONITORING_NR_REGIONS_MIN,
    DAMON_MONITORING_NR_REGIONS_MAX,
    DAMON_MONITORING_MAX,
    DAMON_ACCESS_PATTERN_SZ_MIN,
    DAMON_ACCESS_PATTERN_SZ_MAX,
    DAMON_ACCESS_PATTERN_NR_ACCESSES_MIN,
    DAMON_ACCESS_PATTERN_NR_ACCESSES_MAX,
    DAMON_ACCESS_PATTERN_AGE_MIN,
    DAMON_ACCESS_PATTERN_AGE_MAX,
    DAMON_SCHEMES_ACTION,
    DAMON_ACCESS_PATTERN_MAX,
    DAMON_KDAMONDS_NR,
    DAMON_CONTEXTS_NR,
    DAMON_SCHEMES_NR,
    DAMON_TARGETS_NR,
    DAMON_NR_MAX,
    DAMON_ATTRS_NONE,
};

static char *kdamond_base(void)
{
    char *path = NULL;

    path = (char *)calloc(DAMON_SYSFS_PATH_SIZE, sizeof(char));
    if (path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc memory for %s failed.\n",
                   __func__);
        return NULL;
    }

    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1, "%s/",
                   DAMON_SYSFS_KDAMONDS_DIR) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf kdamond_base failed.\n");
        free(path);
        return NULL;
    }

    return path;
}

static char *kdamond_dir(const struct damon_idx idx)
{
    char *path = NULL;

    path = kdamond_base();
    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1, "%s/%ld/",
                   path, idx.kdamond_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf kdamond_dir failed.\n");
        free(path);
        return NULL;
    }

    return path;
}

static char *contexts_base(const struct damon_idx idx)
{
    char *path = NULL;

    path = (char *)calloc(DAMON_SYSFS_PATH_SIZE, sizeof(char));
    if (path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc memory for %s failed.\n",
                   __func__);
        return NULL;
    }

    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1, "%s/%ld/contexts/",
                   DAMON_SYSFS_KDAMONDS_DIR, idx.kdamond_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf contexts_base failed.\n");
        free(path);
        return NULL;
    }

    return path;
}

static char *targets_base(const struct damon_idx idx)
{
    char *path = NULL;

    path = (char *)calloc(DAMON_SYSFS_PATH_SIZE, sizeof(char));
    if (path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc memory for %s failed.\n",
                   __func__);
        return NULL;
    }

    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1,
                   "%s/%ld/contexts/%ld/targets/", DAMON_SYSFS_KDAMONDS_DIR,
                   idx.kdamond_idx, idx.context_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf targets_base failed.\n");
        free(path);
        return NULL;
    }

    return path;
}

static char *targets_dir(const struct damon_idx idx)
{
    char *path = NULL;

    path = targets_base(idx);
    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1, "%s/%ld/",
                   path, idx.target_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf targets_dir failed.\n");
        free(path);
        return NULL;
    }

    return path;
}

static char *schemes_base(const struct damon_idx idx)
{
    char *path = NULL;

    path = (char *)calloc(DAMON_SYSFS_PATH_SIZE, sizeof(char));
    if (path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc memory for %s failed.\n",
                   __func__);
        return NULL;
    }

    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1,
                   "%s/%ld/contexts/%ld/schemes/", DAMON_SYSFS_KDAMONDS_DIR,
                   idx.kdamond_idx, idx.context_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf schemes_base failed.\n");
        free(path);
        return NULL;
    }
    return path;
}

static char *schemes_dir(const struct damon_idx idx)
{
    char *path = NULL;

    path = schemes_base(idx);
    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1,
                   "%s/%ld/", path, idx.scheme_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf schemes_dir failed.\n");
        free(path);
        return NULL;
    }

    return path;
}

static char *monitoring_attrs_path(const struct damon_idx idx,
                                   enum damon_attrs attr)
{
    char *path = NULL;

    path = (char *)calloc(DAMON_SYSFS_PATH_SIZE, sizeof(char));
    if (path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc memory for %s failed.\n",
                   __func__);
        return NULL;
    }

    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1,
                   "%s/%ld/contexts/%ld/monitoring_attrs/", DAMON_SYSFS_KDAMONDS_DIR,
                   idx.kdamond_idx, idx.context_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf monitoring_attrs_path failed.\n");
        free(path);
        return NULL;
    }

    switch (attr) {
        case DAMON_MONITORING_INTERVALS_AGGR:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "intervals/aggr_us") != EOK)
                goto out_free;
            break;
        case DAMON_MONITORING_INTERVALS_SAMPLE:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "intervals/sample_us") != EOK)
                goto out_free;
            break;
        case DAMON_MONITORING_INTERVALS_UPDATE:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "intervals/update_us") != EOK)
                goto out_free;
            break;
        case DAMON_MONITORING_NR_REGIONS_MAX:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "nr_regions/max") != EOK)
                goto out_free;
            break;
        case DAMON_MONITORING_NR_REGIONS_MIN:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "nr_regions/min") != EOK)
                goto out_free;
            break;
        default:
            break;
    }

    return path;

out_free:
    free(path);
    return NULL;
}

static char *damon_nr_path(const struct damon_idx idx,
                           enum damon_attrs attr)
{
    char *file_name = NULL;

    switch (attr) {
        case DAMON_KDAMONDS_NR:
            file_name = kdamond_base();
            if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "nr_kdamonds") != EOK)
                goto out_free;
            break;
        case DAMON_CONTEXTS_NR:
            file_name = contexts_base(idx);
            if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "nr_contexts") != EOK)
                goto out_free;
            break;
        case DAMON_SCHEMES_NR:
            file_name = schemes_base(idx);
            if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "nr_schemes") != EOK)
                goto out_free;
            break;
        case DAMON_TARGETS_NR:
            file_name = targets_base(idx);
            if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "nr_targets") != EOK)
                goto out_free;
            break;
        default:
            break;
    }

    return file_name;

out_free:
    free(file_name);
    return NULL;
}

static char *access_pattern_path(const struct damon_idx idx,
                                 enum damon_attrs attr)
{
    char *path = NULL;

    path = (char *)calloc(DAMON_SYSFS_PATH_SIZE, sizeof(char));
    if (path == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc memory for %s failed.\n",
                   __func__);
        return NULL;
    }

    if (snprintf_s(path, DAMON_SYSFS_PATH_SIZE, DAMON_SYSFS_PATH_SIZE - 1,
                   "%s/%ld/contexts/%ld/schemes/%ld/access_pattern/",
                   DAMON_SYSFS_KDAMONDS_DIR, idx.kdamond_idx, idx.context_idx,
                   idx.scheme_idx) <= 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) sprintf access_pattern_path failed.\n");
        free(path);
        return NULL;
    }

    switch (attr) {
        case DAMON_ACCESS_PATTERN_AGE_MAX:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "age/max") != EOK)
                goto out_free;
            break;
        case DAMON_ACCESS_PATTERN_AGE_MIN:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "age/min") != EOK)
                goto out_free;
            break;
        case DAMON_ACCESS_PATTERN_NR_ACCESSES_MAX:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "nr_accesses/max") != EOK)
                goto out_free;
            break;
        case DAMON_ACCESS_PATTERN_NR_ACCESSES_MIN:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "nr_accesses/min") != EOK)
                goto out_free;
            break;
        case DAMON_ACCESS_PATTERN_SZ_MAX:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "sz/max") != EOK)
                goto out_free;
            break;
        case DAMON_ACCESS_PATTERN_SZ_MIN:
            if (strcat_s(path, DAMON_SYSFS_PATH_SIZE, "sz/min") != EOK)
                goto out_free;
            break;
        case DAMON_ACCESS_PATTERN_MAX:
            break;
        default:
            break;
    }

    return path;

out_free:
    free(path);
    return NULL;
}

static bool check_damon_sysfs_exist(void)
{
    if (access(DAMON_SYSFS_KDAMONDS_DIR, F_OK) != 0) {
        return false;
    }
    return true;
}

static FILE *get_damon_sysfs_file(enum damon_param filetype,
                                  const struct damon_idx idx,
                                  enum damon_attrs attrs)
{
    char *file_name = NULL;
    FILE *fp = NULL;

    switch (filetype) {
        case DAMON_PARAM_PID_TARGETS:
            file_name = targets_dir(idx);
            if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "pid_target") != EOK)
                goto out_free;
            break;
        case DAMON_PARAM_ATTRS:
            file_name = monitoring_attrs_path(idx, attrs);
            break;
        case DAMON_PARAM_STATE:
            file_name = kdamond_dir(idx);
            if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "state") != EOK)
                goto out_free;
            break;
        case DAMON_PARAM_SCHEMES:
            if (attrs == DAMON_SCHEMES_ACTION) {
                file_name = schemes_dir(idx);
                if (strcat_s(file_name, DAMON_SYSFS_PATH_SIZE, "action") != EOK)
                    goto out_free;
            } else
                file_name = access_pattern_path(idx, attrs);
            break;
        case DAMON_PARAM_NR:
            file_name = damon_nr_path(idx, attrs);
            break;
        default:
            etmemd_log(ETMEMD_LOG_ERR, "get damon(sysfs) filetype error %d.\n",
                       filetype);
            goto out;
    }

    etmemd_log(ETMEMD_LOG_DEBUG, "get_damon_sysfs_file %s.\n", file_name);

    fp = fopen(file_name, "r+");
    if (fp == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) open file %s failed.%s\n",
                   file_name, strerror(errno));
    }

out_free:
    free(file_name);
out:
    return fp;
}

static bool is_engs_valid(struct project *proj)
{
    struct engine *eng = proj->engs;

    while (eng != NULL) {
        if (strcmp(eng->name, "damon") != 0) {
            etmemd_log(ETMEMD_LOG_ERR,
                       "engine type %s is not supported, only support damon engine in region scan\n",
                       eng->name);
            return false;
        }
        eng = eng->next;
    }

    return true;
}

static int get_damon_sysfs_pids_val_and_num(struct task *tk, int *nr_tasks)
{
    while (tk != NULL) {
        if (etmemd_get_task_pids(tk, false) != 0) {
            etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) failed to get task pids.\n");
            *nr_tasks = 0;
            return -1;
        }
        (*nr_tasks)++;
        tk = tk->next;
    }

    return 0;
}

static char *get_damon_sysfs_pids_str(struct task *tk, const int nr_tasks)
{
    char *pids = NULL;
    size_t pids_size;
    char tmp_pid[DAMON_PID_STR_MAX_LEN] = {0};

    pids_size = (DAMON_PID_STR_MAX_LEN - 1) * nr_tasks + 1;
    pids = (char *)calloc(pids_size, sizeof(char));
    if (pids == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) malloc for pids failed.\n");
        return NULL;
    }

    while (tk != NULL) {
        if (snprintf_s(tmp_pid, DAMON_PID_STR_MAX_LEN, DAMON_PID_STR_MAX_LEN - 1,
                       "%u ", tk->pids->pid) == -1) {
            etmemd_log(ETMEMD_LOG_WARN, "damon(sysfs) snprintf pid %u failed.\n",
                       tk->pids->pid);
            tk = tk->next;
            continue;
        }

        if (strcat_s(pids, pids_size, tmp_pid) != EOK) {
            etmemd_log(ETMEMD_LOG_WARN, "damon(sysfs) strcat pid %s failed.\n",
                       tmp_pid);
        }
        tk = tk->next;
    }

    return pids;
}

static int set_damon_sysfs_target_ids(struct project *proj)
{
    FILE *fp = NULL;
    int nr_tasks = 0;
    struct task *tk = proj->engs->tasks;
    char *pids_str = NULL;
    char *pchr = NULL;
    size_t pids_len;
    int ret = -1;
    struct damon_idx idx = {0, 0, 0, 0};

    if (!is_engs_valid(proj)) {
        goto out;
    }

    if (get_damon_sysfs_pids_val_and_num(tk, &nr_tasks) != 0) {
        goto out;
    }

    pids_str = get_damon_sysfs_pids_str(tk, nr_tasks);
    if (pids_str == NULL) {
        goto out_free;
    }

    pids_len = strlen(pids_str);
    if (pids_len == 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) get task pid failed.\n");
        goto out_free;
    }

    pchr = strchr(pids_str, ' ');
    if (pchr)
        *pchr = '\n';

    fp = get_damon_sysfs_file(DAMON_PARAM_PID_TARGETS, idx, DAMON_ATTRS_NONE);
    if (fp == NULL) {
        goto out_free;
    }

    if (fwrite(pids_str, sizeof(char), pids_len, fp) != pids_len) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) write pids failed.\n");
        goto out_close;
    }
    ret = 0;

out_close:
    (void)fclose(fp);
out_free:
    free(pids_str);
out:
    return ret;
}

static char *get_damon_sysfs_attrs_str(struct project *proj)
{
    char *attrs = NULL;
    size_t attrs_size;
    struct region_scan *reg_scan = (struct region_scan *)proj->scan_param;

    attrs_size = (INT_MAX_LEN + 1) * NUM_OF_ATTRS;
    attrs = (char *)calloc(attrs_size, sizeof(char));
    if (attrs == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) malloc for attrs failed.\n");
        return NULL;
    }

    if (snprintf_s(attrs, attrs_size, attrs_size - 1, "%lu %lu %lu %lu %lu",
                   reg_scan->sample_interval, reg_scan->aggr_interval,
                   reg_scan->update_interval, reg_scan->min_nr_regions,
                   reg_scan->max_nr_regions) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) snprintf for attrs failed.\n");
        free(attrs);
        return NULL;
    }

    return attrs;
}

static int set_damon_sysfs_attrs(struct project *proj)
{
    FILE *fp = NULL;
    char *attrs_str = NULL;
    char *attr = NULL;
    size_t attr_len;
    int ret = -1;
    int i = 0;
    struct damon_idx idx = {0, 0, 0, 0};

    attrs_str = get_damon_sysfs_attrs_str(proj);
    if (attrs_str == NULL) {
        goto out;
    }

    attr = strtok(attrs_str, " ");
    for (i = 0; i < DAMON_MONITORING_MAX; i++) {
        etmemd_log(ETMEMD_LOG_DEBUG, "damon(sysfs) %s %s\n", __func__, attr);
        fp = get_damon_sysfs_file(DAMON_PARAM_ATTRS, idx, i);
        if (fp == NULL) {
            goto out;
        }

        attr_len = strlen(attr);
        if (fwrite(attr, sizeof(char), attr_len + 1, fp) != attr_len + 1) {
            etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) write attrs failed.\n");
            fclose(fp);
            goto out_free;
        }
        (void)fclose(fp);
        attr = strtok(NULL, " ");
    }
    ret = 0;

out_free:
    free(attrs_str);
out:
    return ret;
}

static char *get_damon_schemes_str(struct project *proj)
{
    char *schemes = NULL;
    size_t schemes_size;
    struct damon_eng_params *params = (struct damon_eng_params *)proj->engs->params;

    schemes_size = (INT_MAX_LEN + 1) * NUM_OF_SCHEMES;
    schemes = (char *)calloc(schemes_size, sizeof(char));
    if (schemes == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) malloc for schemes failed.\n");
        return NULL;
    }

    if (snprintf_s(schemes, schemes_size, schemes_size - 1, "%lu %lu %u %u %u %u %s",
                   params->min_sz_region, params->max_sz_region,
                   params->min_nr_accesses, params->max_nr_accesses,
                   params->min_age_region, params->max_age_region,
                   params->action_str) == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) snprintf for schemes failed.\n");
        free(schemes);
        return NULL;
    }

    return schemes;
}


static int set_damon_sysfs_schemes(struct project *proj)
{
    FILE *fp = NULL;
    char *schemes_str = NULL;
    int ret = -1;
    char *attr = NULL;
    size_t attr_len;
    int i = 0;
    struct damon_idx idx = {0, 0, 0, 0};

    schemes_str = get_damon_schemes_str(proj);
    if (schemes_str == NULL) {
        goto out;
    }

    etmemd_log(ETMEMD_LOG_DEBUG, "damon(sysfs) %s %s.\n", __func__, schemes_str);
    attr = strtok(schemes_str, " ");
    for (i = DAMON_ACCESS_PATTERN_SZ_MIN; i < DAMON_ACCESS_PATTERN_MAX; i++) {
        fp = get_damon_sysfs_file(DAMON_PARAM_SCHEMES, idx, i);
        if (fp == NULL) {
            goto out;
        }

        attr_len = strlen(attr);
        etmemd_log(ETMEMD_LOG_DEBUG, "damon(sysfs) %s attr=%s.\n",
                   __func__, attr);
        if (fwrite(attr, sizeof(char), attr_len + 1, fp) != attr_len + 1) {
            etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) write schemes failed.\n");
            (void)fclose(fp);
            goto out_free;
        }
        (void)fclose(fp);
        attr = strtok(NULL, " ");
    }

    ret = 0;

out_free:
    free(schemes_str);
out:
    return ret;
}

static char *get_damon_state_str(bool start)
{
    char *state_str = NULL;
    size_t state_size;

    state_size = start ? ON_LEN + 1 : OFF_LEN + 1;
    state_str = (char *)calloc(state_size, sizeof(char));
    if (state_str == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) malloc for state failed.\n");
        return NULL;
    }
    if (snprintf_s(state_str, state_size, state_size - 1, start ? "on" : "off") == -1) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) snprintf for state failed.\n");
        free(state_str);
        return NULL;
    }

    return state_str;
}

static int set_damon_sysfs_state(bool start)
{
    FILE *fp = NULL;
    int ret = -1;
    char *state_str = NULL;
    size_t state_len;
    struct damon_idx idx = {0, 0, 0, 0};

    fp = get_damon_sysfs_file(DAMON_PARAM_STATE, idx, DAMON_ATTRS_NONE);
    if (fp == NULL) {
        goto out;
    }

    state_str = get_damon_state_str(start);
    if (state_str == NULL) {
        goto out_close;
    }

    etmemd_log(ETMEMD_LOG_DEBUG, "damon(sysfs) write %s to state.\n", state_str);
    state_len = strlen(state_str);
    if (fwrite(state_str, sizeof(char), state_len + 1, fp) != state_len + 1) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) write %s to state failed.\n",
                   state_str);
        goto out_free;
    }
    ret = 0;

out_free:
    free(state_str);
out_close:
    (void)fclose(fp);
out:
    return ret;
}

static int damon_sysfs_ensure_dirs(void)
{
    FILE *fp = NULL;
    int ret = -1;
    int i = 0;
    struct damon_idx idx = {0, 0, 0, 0};

    for (i = DAMON_KDAMONDS_NR; i < DAMON_NR_MAX; i++) {
        fp = get_damon_sysfs_file(DAMON_PARAM_NR, idx, i);
        if (fp == NULL) {
            goto out;
        }

        if (fwrite("1\n", sizeof(char), 1, fp) != 1) {
            etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) write 1 to nr failed.\n");
            (void)fclose(fp);
            goto out;
        }

        (void)fclose(fp);
    }
    ret = 0;

out:
    return ret;
}

int etmemd_start_damon(struct project *proj)
{
    bool start = true;

    if (proj == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) proj should not be NULL.\n");
        return -1;
    }

    if (!check_damon_sysfs_exist()) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) kernel module does not exist.\n");
        return -1;
    }

    if (damon_sysfs_ensure_dirs() != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) ensure dirs failed.\n");
        return -1;
    }

    if (set_damon_sysfs_target_ids(proj) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) set pids failed.\n");
        return -1;
    }

    if (set_damon_sysfs_attrs(proj) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) set attrs failed.\n");
        return -1;
    }

    if (set_damon_sysfs_schemes(proj) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) set schemes failed.\n");
        return -1;
    }

    if (set_damon_sysfs_state(start) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) set state to on failed.\n");
        return -1;
    }

    return 0;
}

int etmemd_stop_damon(void)
{
    bool start = false;

    if (!check_damon_sysfs_exist()) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) kernel module does not exist.\n");
        return -1;
    }

    if (set_damon_sysfs_state(start) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) set state to off failed.\n");
        return -1;
    }

    return 0;
}

static int fill_min_size(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    unsigned long min_size = parse_to_ulong(val);

    params->min_sz_region = min_size;
    return 0;
}

static int fill_max_size(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    unsigned long max_size = parse_to_ulong(val);

    params->max_sz_region = max_size;
    return 0;
}

static int fill_min_acc(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    unsigned int min_acc = parse_to_uint(val);

    params->min_nr_accesses = min_acc;
    return 0;
}

static int fill_max_acc(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    unsigned int max_acc = parse_to_uint(val);

    params->max_nr_accesses = max_acc;
    return 0;
}

static int fill_min_age(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    unsigned int min_age = parse_to_uint(val);

    params->min_age_region = min_age;
    return 0;
}

static int fill_max_age(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    unsigned int max_age = parse_to_uint(val);

    params->max_age_region = max_age;
    return 0;
}

static struct action_item damon_action_items[] = {
    {"willneed", DAMOS_WILLNEED},
    {"cold", DAMOS_COLD},
    {"pageout", DAMOS_PAGEOUT},
    {"hugepage", DAMOS_HUGEPAGE},
    {"nohugepage", DAMOS_NOHUGEPAGE},
    {"stat", DAMOS_STAT},
};

static int fill_action(void *obj, void *val)
{
    struct damon_eng_params *params = (struct damon_eng_params *)obj;
    char *action = (char *)val;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(damon_action_items); i++) {
        if (strcmp(action, damon_action_items[i].action_str) == 0) {
            params->action = damon_action_items[i].action_type;
            params->action_str = damon_action_items[i].action_str;
            free(action);
            return 0;
        }
    }

    free(action);
    return -1;
}

static struct config_item damon_eng_config_items[] = {
    {"min_size", INT_VAL, fill_min_size, false},
    {"max_size", INT_VAL, fill_max_size, false},
    {"min_acc", INT_VAL, fill_min_acc, false},
    {"max_acc", INT_VAL, fill_max_acc, false},
    {"min_age", INT_VAL, fill_min_age, false},
    {"max_age", INT_VAL, fill_max_age, false},
    {"action", STR_VAL, fill_action, false},
};

static int damon_fill_eng(GKeyFile *config, struct engine *eng)
{
    struct damon_eng_params *params = calloc(1, sizeof(struct damon_eng_params));

    if (params == NULL) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) alloc engine params failed.\n");
        return -1;
    }

    if (parse_file_config(config, ENG_GROUP, damon_eng_config_items,
        ARRAY_SIZE(damon_eng_config_items), (void *)params) != 0) {
        etmemd_log(ETMEMD_LOG_ERR, "damon(sysfs) fill engine params failed.\n");
        free(params);
        return -1;
    }

    eng->params = (void *)params;
    return 0;
}

static void damon_clear_eng(struct engine *eng)
{
    struct damon_eng_params *eng_params = (struct damon_eng_params *)eng->params;

    if (eng_params == NULL) {
        return;
    }

    free(eng_params);
    eng->params = NULL;
}

struct engine_ops g_damon_sysfs_eng_ops = {
    .fill_eng_params = damon_fill_eng,
    .clear_eng_params = damon_clear_eng,
    .fill_task_params = NULL,
    .clear_task_params = NULL,
    .start_task = NULL,
    .stop_task = NULL,
    .alloc_pid_params = NULL,
    .free_pid_params = NULL,
    .eng_mgt_func = NULL,
};

int fill_engine_type_damon(struct engine *eng, GKeyFile *config)
{
    eng->ops = &g_damon_sysfs_eng_ops;
    eng->engine_type = DAMON_ENGINE;
    eng->name = "damon";
    return 0;
}
