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
 * Author: shikemeng
 * Create: 2021-4-30
 * Description: This is a header file of the export project symbols.
 ******************************************************************************/

#ifndef ETMEMD_PROJECT_EXP_H
#define ETMEMD_PROJECT_EXP_H

#include <sys/queue.h>
#include <stdbool.h>

struct project {
    char *name;
    int interval;
    int loop;
    int sleep;
    bool start;
    struct engine *engs;

    SLIST_ENTRY(project) entry;
};

#endif
