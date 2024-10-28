# etmem

## 介绍

随着CPU算力的发展，尤其是ARM核成本的降低，内存成本和内存容量成为约束业务成本和性能的核心痛点，因此如何节省内存成本，如何扩大内存容量成为存储迫切要解决的问题。

etmem内存分级扩展技术，通过DRAM+内存压缩/高性能存储新介质形成多级内存存储，对内存数据进行分级，将分级后的内存冷数据从内存介质迁移到高性能存储介质中，达到内存容量扩展的目的，从而实现内存成本下降。

## 编译教程

1. 下载etmem源码

    $ git clone https://gitee.com/openeuler/etmem.git

2. 编译和运行依赖

    etmem的编译和运行依赖于libboundscheck组件
    ```
    yum install libboundscheck
    ```

3. 编译

    $ cd etmem

    $ mkdir build

    $ cd build

    $ cmake ..

    $ make


## 注意事项
### 运行依赖
etmem作为内存扩展工具，需要依赖于内核态的特性支持，为了可以识别内存访问情况和支持主动将内存写入swap分区来达到内存垂直扩展的需求，etmem在运行时需要插入etmem_scan和etmem_swap模块：

```
modprobe etmem_scan
modprobe etmem_swap
```
openuler21.03、21.09、20.03 LTS SP2以及20.03 LTS SP3均支持etmem内存扩展相关特性，可以直接使用以上内核。

### 权限限制
运行etmem进程需要root权限，root用户具有系统最高权限，在使用root用户进行操作时，请严格按照操作指导进行操作，避免其他操作造成系统管理及安全风险。

### 使用约束

- etmem的客户端和服务端需要在同一个服务器上部署，不支持跨服务器通信的场景。
- etmem仅支持扫描进程名小于或等于15个字符长度的目标进程。
- 在使用AEP介质进行内存扩展的时候，依赖于系统可以正确识别AEP设备并将AEP设备初始化为numa node。并且配置文件中的vm_flags字段只能配置为ht。
- 引擎私有命令仅针对对应引擎和引擎下的任务有效，比如cslide所支持的showhostpages和showtaskpages。
- 第三方策略实现代码中，eng_mgt_func接口中的fd不能写入0xff和0xfe字。
- 支持在一个工程内添加多个不同的第三方策略动态库，以配置文件中的eng_name来区分。
- 禁止并发扫描同一个进程。未加载etmem_scan和etmem_swap ko时，禁止使用/proc/xxx/idle_pages和/proc/xxx/swap_pages文件


## 使用说明

### 启动etmemd进程

#### 使用方法

通过运行etmemd二进制运行服务端进程，例如：

$ etmemd -l 0 -s etmemd_socket

#### 帮助信息

options：

-l|\-\-log-level <log-level>  Log level

-s|\-\-socket <sockect name>  Socket name to listen to

-h|\-\-help  Show this message

-m|\-\-mode-systemctl mode used to start(systemctl)

#### 命令行参数说明

| 参数            | 参数含义                           | 是否必须 | 是否有参数 | 参数范围              | 示例说明                                                     |
| --------------- | ---------------------------------- | -------- | ---------- | --------------------- | ------------------------------------------------------------ |
| -l或\-\-log-level | etmemd日志级别                     | 否       | 是         | 0~3                   | 0：debug级别   1：info级别   2：warning级别   3：error级别   只有大于等于配置的级别才会打印到/var/log/messages文件中 |
| -s或\-\-socket    | etmemd监听的名称，用于与客户端交互 | 是       | 是         | 107个字符之内的字符串 | 指定服务端监听的名称                                         |
| -h或\-\-help      | 帮助信息                           | 否       | 否         | NA                    | 执行时带有此参数会打印后退出                                 |
| -m或\-\-mode-systemctl|	etmemd作为service被拉起时，命令中可以使用此参数来支持fork模式启动|	否|	否|	NA|	NA|
### etmem配置文件

在运行etmem进程之前，需要管理员预先规划哪些进程需要做内存扩展，将进程信息配置到etmem配置文件中，并配置内存扫描的周期、扫描次数、内存冷热阈值等信息。

配置文件的示例文件在源码包中，放置在/etc/etmem文件路径下，按照功能划分为3个示例文件，

```
/etc/etmem/cslide_conf.yaml
/etc/etmem/slide_conf.yaml
/etc/etmem/thirdparty_conf.yaml
```
示例内容分别为：

```
[project]
name=test
loop=1
interval=1
sleep=1

#slide引擎示例
[engine]
name=slide
project=test

[task]
project=test
engine=slide
name=background_slide
type=name
value=mysql
T=1
max_threads=1

#cslide引擎示例
[engine]
name=cslide
project=test
node_pair=2,0;3,1
hot_threshold=1
node_mig_quota=1024
node_hot_reserve=1024

[task]
project=test
engine=cslide
name=background_cslide
type=pid
name=23456
vm_flags=ht
anon_only=no
ign_host=no

#thirdparty引擎示例
[engine]
name=thirdparty
project=test
eng_name=my_engine
libname=/usr/lib/etmem_fetch/my_engine.so
ops_name=my_engine_ops
engine_private_key=engine_private_value

[task]
project=test
engine=my_engine
name=backgroud_third
type=pid
value=12345
task_private_key=task_private_value
```

配置文件各字段说明：

| 配置项       | 配置项含义               | 是否必须 | 是否有参数 | 参数范围       | 示例说明                                                            |
|-----------|---------------------|------|-------|------------|-----------------------------------------------------------------|
| [project] | project公用配置段起始标识    | 否    | 否     | NA         | project参数的开头标识，表示下面的参数直到另外的[xxx]或文件结尾为止的范围内均为project section的参数 |
| name      | project的名字          | 是    | 是     | 64个字以内的字符串 | 用来标识project，engine和task在配置时需要指定要挂载到的project                     |
| loop      | 内存扫描的循环次数           | 是    | 是     | 1~10       | loop=3 //扫描3次                                                   |
| interval  | 每次内存扫描的时间间隔         | 是    | 是     | 1~1200     | interval=5 //每次扫描之间间隔5s                                         |
| sleep     | 每个内存扫描+操作的大周期之间时间间隔 | 是    | 是     | 1~1200     | sleep=10 //每次大周期之间间隔10s                                         |
| sysmem_threshold| slide engine的配置项，系统内存换出阈值 | 否    | 是     | 0~100     | sysmem_threshold=50 //系统内存剩余量小于50%时，etmem才会触发内存换出|
| swapcache_high_wmark| slide engine的配置项，swacache可以占用系统内存的比例，高水线 | 否    | 是     | 1~100     | swapcache_high_wmark=5 //swapcache内存占用量可以为系统内存的5%，超过该比例，etmem会触发swapcache回收<br> 注： swapcache_high_wmark需要大于swapcache_low_wmark|
| swapcache_low_wmark| slide engine的配置项，swacache可以占用系统内存的比例，低水线 | 否    | 是     | [1~swapcache_high_wmark)     | swapcache_low_wmark=3 //触发swapcache回收后，系统会将swapcache内存占用量回收到低于3%|
| [engine]      | engine公用配置段起始标识                           | 否                  | 否     | NA                                               | engine参数的开头标识，表示下面的参数直到另外的[xxx]或文件结尾为止的范围内均为engine section的参数 |
| project       | 声明所在的project                              | 是                  | 是     | 64个字以内的字符串                                       | 已经存在名字为test的project，则可以写为project=test                        |
| engine        | 声明所在的engine                               | 是                  | 是     | slide/cslide/thridparty                          | 声明使用的是slide或cslide或thirdparty策略                              |
| node_pair     | cslide engine的配置项，声明系统中AEP和DRAM的node pair | engine为cslide时必须配置 | 是     | 成对配置AEP和DRAM的node号，AEP和DRAM之间用逗号隔开，没对pair之间用分号隔开 | node_pair=2,0;3,1                                            |
| hot_threshold | cslide engine的配置项，声明内存冷热水线的阈值             | engine为cslide时必须配置 | 是     | >= 0的整数                                          | hot_threshold=3 //访问次数小于3的内存会被识别为冷内存                         |
|node_mig_quota|cslide engine的配置项，流控，声明每次DRAM和AEP互相迁移时单向最大流量|engine为cslide时必须配置|是|>= 0的整数|node_mig_quota=1024 //单位为MB，AEP到DRAM或DRAM到AEP搬迁一次最大1024M|
|node_hot_reserve|cslide engine的配置项，声明DRAM中热内存的预留空间大小|engine为cslide时必须配置|是|>= 0的整数|node_hot_reserve=1024 //单位为MB，当所有虚拟机热内存大于此配置值时，热内存也会迁移到AEP中|
|eng_name|thirdparty engine的配置项，声明engine自己的名字，供task挂载|engine为thirdparty时必须配置|是|64个字以内的字符串|eng_name=my_engine //对此第三方策略engine挂载task时，task中写明engine=my_engine|
|libname|thirdparty engine的配置项，声明第三方策略的动态库的地址，绝对地址|engine为thirdparty时必须配置|是|64个字以内的字符串|libname=/user/lib/etmem_fetch/code_test/my_engine.so|
|ops_name|thirdparty engine的配置项，声明第三方策略的动态库中操作符号的名字|engine为thirdparty时必须配置|是|64个字以内的字符串|ops_name=my_engine_ops //第三方策略实现接口的结构体的名字|
|engine_private_key|thirdparty engine的配置项，预留给第三方策略自己解析私有参数的配置项，选配|否|否|根据第三方策略私有参数自行限制|根据第三方策略私有engine参数自行配置|
| [task]  | task公用配置段起始标识 | 否 | 否 | NA          | task参数的开头标识，表示下面的参数直到另外的[xxx]或文件结尾为止的范围内均为task section的参数 |
| project | 声明所挂的project  | 是 | 是 | 64个字以内的字符串  | 已经存在名字为test的project，则可以写为project=test                     |
| engine  | 声明所挂的engine   | 是 | 是 | 64个字以内的字符串  | 所要挂载的engine的名字                                            |
| name    | task的名字       | 是 | 是 | 64个字以内的字符串  | name=background1 //声明task的名字是backgound1                   |
| type    | 目标进程识别的方式     | 是 | 是 | pid/name    | pid代表通过进程号识别，name代表通过进程名称识别                               |
| value   | 目标进程识别的具体字段   | 是 | 是 | 实际的进程号/进程名称 | 与type字段配合使用，指定目标进程的进程号或进程名称，由使用者保证配置的正确及唯一性               |
| T                | engine为slide的task配置项，声明内存冷热水线的阈值                               | engine为slide时必须配置 | 是 | 0~loop * 3           | T=3 //访问次数小于3的内存会被识别为冷内存                                        |
| max_threads      | engine为slide的task配置项，etmemd内部线程池最大线程数，每个线程处理一个进程/子进程的内存扫描+操作任务 | 否                 | 是 | 1~2 * core数 + 1，默认为1 | 对外部无表象，控制etmemd服务端内部处理线程个数，当目标进程有多个子进程时，配置越大，并发执行的个数也多，但占用资源也越多 |
| vm_flags         | engine为cslide的task配置项，通过指定flag扫描的vma，不配置此项时扫描则不会区分             | engine为cslide时必须配置                 | 是 | 当前只支持ht           | vm_flags=ht //扫描flags为ht（大页）的vma内存                              |
| anon_only        | engine为cslide的task配置项，标识是否只扫描匿名页                               | 否                 | 是 | yes/no               | anon_only=no //配置为yes时只扫描匿名页，配置为no时非匿名页也会扫描                     |
| ign_host         | engine为cslide的task配置项，标识是否忽略host上的页表扫描信息                       | 否                 | 是 | yes/no               | ign_host=no //yes为忽略，no为不忽略                                     |
| task_private_key | engine为thirdparty的task配置项，预留给第三方策略的task解析私有参数的配置项，选配           | 否                 | 否 | 根据第三方策略私有参数自行限制      | 根据第三方策略私有task参数自行配置                                             |
| swap_threshold |slide engine的配置项，进程内存换出阈值           | 否                 | 是 | 进程可用内存绝对值      | swap_threshold=10g //进程占用内存在低于10g时不会触发换出。<br>当前版本下，仅支持g/G作为内存绝对值单位。与sysmem_threshold配合使用，仅系统内存低于阈值时，进行白名单中进程阈值判断 |
| swap_flag|slide engine的配置项，进程指定内存换出           | 否                 | 是 | yes/no      | swap_flag=yes//使能进程指定内存换出 |


### etmem project/engine/task对象的创建和删除

#### 场景描述

1）管理员创建etmem的project/engine/task（一个工程可包含多个etmem engine，一个engine可以包含多个任务）

2）管理员删除已有的etmem project/engine/task（删除工程前，会自动先停止该工程中的所有任务）

#### 使用方法

运行etmem二进制，通过第二个参数指定为obj，来进行创建或删除动作，对project/engine/task则是通过配置文件中配置的内容来进行识别和区分。前提是etmem配置文件已配置正确，etmemd进程已启动。

添加对象：

etmem obj add -f /etc/etmem/slide_conf.yaml -s etmemd_socket

删除对象：

etmem obj del -f /etc/etmem/slide_conf.yaml -s etmemd_socket

打印帮助：

etmem obj help

#### 帮助信息

Usage:

etmem obj add [options]

etmem obj del [options]

etmem obj help

Options:

-f|\-\-file <conf_file> Add configuration file

-s|\-\-socket <socket_name> Socket name to connect

Notes:

1. Configuration file must be given.

#### 命令行参数说明


| 参数         | 参数含义                                                     | 是否必须 | 是否有参数 | 示例说明                                                 |
| ------------ | ------------------------------------------------------------ | -------- | ---------- | -------------------------------------------------------- |
| -f或\-\-file   | 指定对象的配置文件                                        | add，del子命令必须包含       | 是         | 需要指定路径名称                                         |
| -s或\-\-socket | 与etmemd服务端通信的socket名称，需要与etmemd启动时指定的保持一致 | add，del子命令必须包含       | 是         | 必须配置，在有多个etmemd时，由管理员选择与哪个etmemd通信 |

### etmem任务启动/停止/查询

#### 场景描述

在已经通过etmem obj add添加工程之后，在还未调用etmem obj del删除工程之前，可以对etmem的工程进行启动和停止。

1）管理员启动已添加的工程

2）管理员停止已启动的工程

在管理员调用obj del删除工程时，如果工程已经启动，则会自动停止。

#### 使用方法

对于已经添加成功的工程，可以通过etmem project的命令来控制工程的启动和停止，命令示例如下：

启动工程

etmem project start -n test -s etmemd_socket

停止工程

etmem project stop -n test -s etmemd_socket

查询工程

etmem project show -n test -s etmemd_socket

打印帮助

etmem project help

#### 帮助信息

Usage:

etmem project start [options]

etmem project stop [options]

etmem project show [options]

etmem project help

Options:

-n|\-\-name <proj_name> Add project name

-s|\-\-socket <socket_name> Socket name to connect

Notes:

1. Project name and socket name must be given when execute add or del option.

2. Socket name must be given when execute show option.

#### 命令行参数说明

| 参数         | 参数含义                                                     | 是否必须 | 是否有参数 | 示例说明                                                 |
| ------------ | ------------------------------------------------------------ | -------- | ---------- | -------------------------------------------------------- |
| -n或\-\-name   | 指定project名称                                              | start，stop，show子命令必须包含      | 是         | project名称，与配置文件一一对应                          |
| -s或\-\-socket | 与etmemd服务端通信的socket名称，需要与etmemd启动时指定的保持一致 | start，stop，show子命令必须包含       | 是         | 必须配置，在有多个etmemd时，由管理员选择与哪个etmemd通信 |

### etmem支持随系统自启动

#### 场景描述

etmemd支持由用户配置systemd配置文件后，以fork模式作为systemd服务被拉起运行

#### 使用方法

编写service配置文件，来启动etmemd，必须使用-m参数来指定此模式，例如

etmemd -l 0 -s etmemd_socket -m

#### 帮助信息

options:

-l|\-\-log-level <log-level> Log level

-s|\-\-socket <sockect name> Socket name to listen to

-m|\-\-mode-systemctl mode used to start(systemctl)

-h|\-\-help Show this message

#### 命令行参数说明
| 参数             | 参数含义       | 是否必须 | 是否有参数 | 参数范围 | 实例说明      |
|----------------|------------|------|-------|------|-----------|
| -l或\-\-log-level | etmemd日志级别 | 否    | 是     | 0~3  | 0：debug级别；1：info级别；2：warning级别；3：error级别；只有大于等于配置的级别才会打印到/var/log/messages文件中|
| -s或\-\-socket |etmemd监听的名称，用于与客户端交互 |	是	| 是|	107个字符之内的字符串|	指定服务端监听的名称|
|-m或\-\-mode-systemctl	| etmemd作为service被拉起时，命令中需要指定此参数来支持 |	否 |	否 |	NA |	NA |
| -h或\-\-help |	帮助信息 |	否	 |否	|NA	|执行时带有此参数会打印后退出|




### etmem支持第三方内存扩展策略

#### 场景描述

etmem支持用户注册第三方内存扩展策略，同时提供扫描模块动态库，运行时通过第三方策略淘汰算法淘汰内存。

用户使用etmem所提供的扫描模块动态库并实现对接etmem所需要的结构体中的接口

#### 使用方法

用户使用自己实现的第三方扩展淘汰策略，主要需要按下面步骤进行实现和操作：

1. 按需调用扫描模块提供的扫描接口，

2. 按照etmem头文件中提供的函数模板来实现各个接口，最终封装成结构体

3. 编译出第三方扩展淘汰策略的动态库

4. 在配置文件中按要求声明类型为thirdparty的engine

5. 将动态库的名称和接口结构体的名称按要求填入配置文件中task对应的字段

其他操作步骤与使用etmem的其他engine类似

接口结构体模板

struct engine_ops {

/* 针对引擎私有参数的解析，如果有，需要实现，否则置NULL */

int (*fill_eng_params)(GKeyFile *config, struct engine *eng);

/* 针对引擎私有参数的清理，如果有，需要实现，否则置NULL */

void (*clear_eng_params)(struct engine *eng);

/* 针对任务私有参数的解析，如果有，需要实现，否则置NULL */

int (*fill_task_params)(GKeyFile *config, struct task *task);

/* 针对任务私有参数的清理，如果有，需要实现，否则置NULL */

void (*clear_task_params)(struct task *tk);

/* 启动任务的接口 */

int (*start_task)(struct engine *eng, struct task *tk);

/* 停止任务的接口 */

void (*stop_task)(struct engine *eng, struct task *tk);

/* 填充pid相关私有参数 */

int (*alloc_pid_params)(struct engine *eng, struct task_pid **tk_pid);

/* 销毁pid相关私有参数 */

void (*free_pid_params)(struct engine *eng, struct task_pid **tk_pid);

/* 第三方策略自身所需要的私有命令支持，如果没有，置为NULL */

int (*eng_mgt_func)(struct engine *eng, struct task *tk, char *cmd, int fd);

};

配置文件示例如下所示，具体含义请参考配置文件说明章节：

#thirdparty

[engine]

name=thirdparty

project=test

eng_name=my_engine

libname=/user/lib/etmem_fetch/code_test/my_engine.so

ops_name=my_engine_ops

engine_private_key=engine_private_value

[task]

project=test

engine=my_engine

name=background1

type=pid

value=1798245

task_private_key=task_private_value

 **注意** ：

用户需使用etmem所提供的扫描模块动态库并实现对接etmem所需要的结构体中的接口

eng_mgt_func接口中的fd不能写入0xff和0xfe字

支持在一个工程内添加多个不同的第三方策略动态库，以配置文件中的eng_name来区分

### etmem支持使用AEP进行内存扩展

#### 场景描述

使用etmem组件包，使能内存分级扩展至AEP的通路。

在节点内对虚拟机的大页进行扫描，并通过cslide引擎进行策略淘汰，将冷内存搬迁至AEP中

#### 使用方法

使用cslide引擎进行内存扩展，参数示例如下，具体参数含义请参考配置文件说明章节

#cslide

[engine]

name=cslide

project=test

node_pair=2,0;3,1

hot_threshold=1

node_mig_quota=1024

node_hot_reserve=1024

[task]

project=test

engine=cslide

name=background1

type=pid

value=1823197

vm_flags=ht

anon_only=no

ign_host=no

 **注意** ：禁止并发扫描同一个进程

同时，此cslide策略支持私有的命令


- showtaskpages
- showhostpages

针对使用此策略引擎的engine和engine所有的task，可以通过这两个命令分别查看task相关的页面访问情况和虚拟机的host上系统大页的使用情况。

示例命令如下：

etmem engine showtaskpages <-t task_name> -n proj_name -e cslide -s etmemd_socket

etmem engine showhostpages -n proj_name -e cslide -s etmemd_socket

 **注意** ：showtaskpages和showhostpages仅支持引擎使用cslide的场景

#### 命令行参数说明
| 参数 | 参数含义 | 是否必须 | 是否有参数 | 实例说明 |
|----|------|------|-------|------|
|-n或\-\-proj_name|	指定project的名字|	是|	是|	指定已经存在，所需要执行的project的名字|
|-s或\-\-socket|	与etmemd服务端通信的socket名称，需要与etmemd启动时指定的保持一致|	是|	是|	必须配置，在有多个etmemd时，由管理员选择与哪个etmemd通信|
|-e或\-\-engine|	指定执行的引擎的名字|	是|	是|	指定已经存在的，所需要执行的引擎的名字|
|-t或\-\-task_name|	指定执行的任务的名字|	否|	是|	指定已经存在的，所需要执行的任务的名字|

### etmem支持利用PSI策略使能cgroup 粒度内存扩展
PSI 特性能够识别和量化资源竞争导致的业务中断，及其对复杂负载乃至整个系统在时间上的影响。
etmem 通过获取 psi 压力信息，动态调节每轮的换出内存量，从而降低内存换出后对整体业务性能的影响。
[PSI的相关资料介绍](https://www.kernel.org/doc/html/v5.17/translations/zh_CN/accounting/psi.html)

#### 场景描述
使用etmem组件包，在cgroup v1场景下，不断检测 cgroup 中PSI 控制参数，查看PSI压力情况是否满足要求，动态调整cgroup 粒度的内存占用量，达到cgroup 粒度内存扩展的目的。

#### 注意事项
1. etmem 在使用PSI策略时，依赖内核kernel开启了PSI 配置，即内核cmdline 中需要添加启动参数：
```
psi=1 psi_v1=1
```
并且确保内核打开了CGROUP_V1相关参数：
```
CONFIG_PSI_CGROUP_V1=y
```
2. etmem 利用swap内存到其他介质的方式来实现内存扩展，因此，在启动etmem前需要先挂载swap分区，可以直接挂载磁盘作为swap分区，或利用ZRAM方式进行挂载。
* 磁盘作为swap分区
```
fdisk /dev/nvme1n1 创建swap分区
mkswap /dev/nvme1n1p1
swapon /dev/nvme1n1p1
swapon -s          查看swap分区
```

* ZRAM作为swap分区
```
modprobe zram
echo 90G > /sys/block/zram0/disksize
mkswap /dev/zram0
swapon /dev/zram0
swapon -s          查看swap分区
```

#### 使用方法
1、启动etmemd 进程
```shell
etmemd -l 0 -s etmemd_socket &
# 命令行参数信息见 启动etmemd 进程章节
````

2、编写PSI策略配置文件
示例配置文件如下：
```
[project]
name=test
scan_type=psi
interval=6

[engine]
name=psi
project=test

[task]
project=test
engine=psi
name=psi_task
cg_dir=isulad
pressure=0.1
reclaim_rate=0.01
limit_min_bytes=209715200
```

**配置参数含义与解释如下：**
| 参数 | 参数含义 | 是否必须 | 是否有参数 | 实例说明 |
|----|------|------|-------|------|
|[project]]|	project公用配置段起始标识|	否|	否|	NA|
|name|	指定project的名字|	是|	是|	64个字符以内的字符串|
|scan_type|	扫描类型，PSI策略下指定为psi|	是|	是|	必须配置，psi|
|interval|	每轮扫描换出的周期|	是|	是|	1~1200|
|[engine]|	engine公用配置段起始标识|	否|	否|	NA|
|project|	声明所在的project|	是|	是|	64个字以内的字符串|
|name|	指定engine的名字|	是|	是|	64个字符以内的字符串|
|[task]|	task公用配置段起始标识|	否|	否|	NA|
|project|	声明所在的project|	是|	是|	64个字以内的字符串|
|engine|	声明所在的engine|	是|	是|	64个字以内的字符串|
|name|	task的名字|	是|	是|	64个字符以内的字符串|
|cg_dir|	要换出的cgroup名称|	是|	是|	实际的cgroup名称,最大长度64个字符，例如cg_dir=isulad，则要求/sys/fs/cgroup/cpu,cpuacct/isulad/目录与/sys/fs/cgroup/memory/isulad/ 存在；或cg_dir=isulad/*,通配符方式配置，表明/sys/fs/cgroup/cpu/isulad/目录下的所有下一级目录均会添加到task中进行换出控制|
|pressure|	pressure允许的压力大小|	否|	是|	pressure=0.1,不填写的话，默认为0.1|
|reclaim_rate|	每轮回收内存的比例|	否|	是|	reclaim_rate=0.01，每轮回收百分之一的可回收内存，运行过程中会自适应增大或减小，默认为0.05|
|reclaim_rate_max|	每轮回收内存的最大比例|	否|	是|	reclaim_rate_max=0.5，reclaim_rate最大增长到该值，默认为0.5|
|reclaim_rate_min|	每轮回收内存的最小比例|	否|	是|	reclaim_rate_min=0.01，reclaim_rate最小减到该值，默认为0.01|
|reclaim_max_bytes|	每轮回收内存的最大值|	否|	是|	reclaim_max_bytes=209715200，每轮最多回收200M，默认为1G|
|limit_min_bytes|	开始回收的内存阈值|	否|	是|	字节为单位，limit_min_bytes=209715200，该cgroup占用200M内存以上的部分才回收|
|limit_min_ratio|	按内存容量的比例启动回收|	否|	是|	limit_min_ratio=0.2，该cgroup占memory.limit_in_bytes 20%内存以上的部分才回收|

3、加载配置工程与任务

编写完成配置文件后，通过etmem客户端命令加载工程到etmemd服务端。
```shell
etmem obj add -f /etc/etmem/psi_conf.yaml  -s etmemd_socket
```
若需要更新psi_conf.yaml配置信息，可重新添加工程：
```shell
etmem obj del -f /etc/etmem/psi_conf.yaml  -s etmemd_socket
etmem obj add -f /etc/etmem/psi_conf.yaml  -s etmemd_socket
```
若需要添加多个task对应的多个cg_dir信息，可单独配置[task]单元字段，并进行添加：
```shell
etmem obj del -f /etc/etmem/psi_task.yaml  -s etmemd_socket
```

注： 
* 因etmem要操作多个多个cgroup进程的控制字段，基于安全要求，etmem以root权限运行，其配置文件要求权限为600/400.
* 不支持同一个配置文件中添加多个相同的字段[task/engine/project]名称，后面的会覆盖掉前面的，若需要添加多个task，需要多个配置文件

4、启动工程
在已经通过etmem obj add添加工程之后，在还未调用etmem obj del删除工程之前，可以对etmem的工程进行启动和停止。

```shell
etmem project start -n test -s etmemd_socket
```
工程启动后，etmem相关调试日志会存储到/var/log/messages中，每一轮的回收信息会以 **DEBUG**等级打印到/var/log/messages中，可以通过调整日志等级后查看。

5、停止工程
运行结束后，可通过etmem project 命令停止工程。
```shell
etmem project stop -n test -s etmemd_socket
```
查询工程
```shell
etmem project show -n test -s etmemd_socket
```
删除工程
```shell
etmem obj del -f /etc/etmem/psi_task.yaml  -s etmemd_socket
```

### etmem支持利用硬件访存事件进行内存数据分级

#### 编译
在原流程基础上,使用下面指令替换cmake ..
$ cmake -DENABLE_PMU=ON ..  

#### 项目依赖
本项目依赖 libpfm4, 可以指令安装libpfm-devel;
在执行安装指令之后, libpfm4 的头文件通常默认安装到路径 /usr/include/perfmon .
要在cmake项目中正确包含头文件，需要设置环境变量 CMAKE_INCLUDE_PATH .
export CMAKE_INCLUDE_PATH=$CMAKE_INCLUDE_PATH:/usr/include/perfmon  

#### 使用方法
参考etmem/conf/pmu_conf.yaml, 并在[task]添加下面三个配置参数
```shell
[task]
sample_period=5000  
vma_updata_rate=5
cpu_set_size=16
```
若使用cslide引擎,则在etmem/conf/cslide_conf.yaml[engine]添加下面三个配置参数，同时cslide引擎支持设置数据冷处理间隔cooling_interval.
```shell
[engine]
sample_period=5000  
vma_updata_rate=5
cpu_set_size=16
cooling_interval=100000
```

**配置参数含义与解释如下：**
配置文件各字段说明：

| 配置项       | 配置项含义               | 是否必须 | 是否有参数 | 参数范围       | 示例说明                                                            |
|-----------|---------------------|------|-------|------------|-----------------------------------------------------------------|
| sample_period |利用pmu采样内存访问事件的周期     | 使用硬件访存事件时必须设置                 | 是 | [1000,10000]推荐参数范围     | sample_period=5000//表示5000条指令触发一次内存访问事件采样|
| vma_updata_rate | vmas update 频率 | 使用硬件访存事件时必须设置               | 是 | [0,50]推荐参数范围     | vma_updata_rate=5//表示在5*loop*sleep时间做一次vma update |
| cpu_set_size |多少个核用一个线程进行采样 | 使用硬件访存事件时必须设置               | 是 | lscpu 显示的cpu核数的因数，0除外  | cpu_set_size=16//首先我们设定一个核有一个buffer，cpu_set_size=16表示一个线程采样16个buffer里面的访存事件信息, 那么如果64核对应的就有64/16=4个线程进行采样  |
| cooling_interval |多少次采样后做一次数据冷处理 | 使用硬件访存事件时必须设置               | 是 | [10000,1000000]推荐参数范围  | cooling_interval=100000 // 采样循环100000次将采样数据指数平滑移动一次。  |

## 参与贡献

1.  Fork本仓库
2.  新建个人分支
3.  提交代码
4.  新建Pull Request
