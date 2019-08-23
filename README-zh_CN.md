# AgentSmith-HIDS

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;--项目名称灵感来源于电影《黑客帝国》



[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/LICENSE)

[English](README.md) | 简体中文




### 关于AgentSmith-HIDS

AgentSmith-HIDS严格意义上并不是一个“Host-based Intrusion Detection System”，因为目前开源的部分来讲它缺乏了规则引擎和相关检测的功能，但是它可以作为一个高性能“主机情报收集工具”来构建属于你自己的HIDS。
由于AgentSmit-HIDS的特点(从Kernel中获取尽可能全的数据)，对比用户态的HIDS拥有巨大的优势：
* 性能更优，信息一次获取全面，无需诸如遍历/proc这样的行为进行数据补全；传输方案使用共享内存，拒绝netlink。
* 难以绕过，比如：大多数用户态HIDS是通过进程名之类的来检测恶意行为，如反弹shell，极易绕过(cp /bin/bash abc)，且用户态HIDS面对Rootkit或者稍微有一定技巧的黑客往往显得极为无力，但是内核态HIDS不存在这些问题，我们关注的是syscall调用。
* 为联动而生，我们不仅可以作为安全工具，也可以作为监控，内部资产梳理的利器。我们通过Hook Connect/Accept从而实现了对进程/用户/文件/网络连接的全面梳理。如果有CMDB的信息，那么联动后你将会得到一张从网络到主机/容器/业务信息的调用/依赖关系图；如果你们还有DB Audit Tool，那么联动后你可以得到DB User/库表字段/应用/网络/主机容器的关系；等等，还可以和NIDS/威胁情报联动，达到溯源的目的。
* 即使面对Kernel级别Rootkit，想绕过我们的Hook也极为不易。
* 其实我们也有用户态Agent,严格意义上说我们在用户态和内核态都可以做监控(目前用户态Agent主要是接收内核态Agent Hook的信息并转发到Server；保持心跳；接收Server指令运行一些自定义检测模块等)。




### 谁适合AgentSmith-HIDS？

对Linux有一定了解，对HIDS有需求，对现有的HIDS性能/联动能力/误报漏报率/二次开发难度不满意的安全工程师，AgentSmith-HIDS也许是你的选择，AgentSmith-HIDS是为了低性能损耗，异常行为检测和联动能力而生的项目。




### AgentSmith-HIDS实现了以下的功能：

* 通过加载LKM的方式Hook了**execve,connect,ptrace,accept,accept4,init_module,finit_module**的system_call；
* 通过对Linux namespace兼容的方式实现了对Docker容器行为的情报收集；
* 实现了两种将Hook Info从内核态传输到用户态的方式：netlink和共享内存，共享内存传输损耗相较于netlink减小30%，在测试服务器上Hook connect耗时中位数8478ns，更详细的AgentSmith-HIDS BencherMark请见:https://github.com/DianrongSecurity/AgentSmith-HIDS/tree/master/doc **(注:经过其他小伙伴提醒，我们的压力测试方法有一定问题，并不是极限测试，我们会尽快发布更"压力"的测试报告)**
* **系统文件完整性检测**，**系统用户列表查询**，**系统端口监听列表查询**，**系统RPM LIST查询**，**系统定时任务查询**功能；
* 支持自定义检测模块(具体添加方式见下文)
* 实时检测进程注入(Process Injection)
* 实时检测Rootkit(Beta Feature)




### 关于兼容系统及内核版本

* AgentSmith-HIDS 仅在**Centos6/7 Kernel 2.6.32/3.10**上进行过充分的测试.如果有其他人在其他版本上进行过稳定性测试，可以随时联系我们（需附稳定性测试报告）。
* 我们会对AgentSmith-HIDS进行长期维护，会追随Centos7的最新稳定版进行维护。



### 对Docker的兼容

在宿主机上安装AgentSmith-HIDS可以监控宿主机上容器的行为。如果是宿主机行为，nodename为宿主机hostname；如果是原生Docker容器，nodename为container name；如果是k8s，nodename为pod name。




### 关于使用方式

* AgentSmith-HIDS 有一个简陋的用户态demo进行接收LKM传输的信息，并将信息拼接为JSON后传输到Server端，该项目用Rust编写，需要有openssl lib的支持，传输方式采用Kafka传输。
* AgentSmith-HIDS 的定位就是一款轻量级，高性能的情报采集工具，首先可以检测如:反弹shell，执行命令，下载恶意程序，一些Rootkit等等NIDS的死角。其次可以和NIDS/CMDB完成联动，达到：**PID+PPID+nodename+cmdline+cwd+user+exe+TCP/UDP五元组+部分协议的原始数据+业务相关信息+FW_RULE+NIDS/HIDS规则ID+威胁情报信息+等**的联动效果。



### 关于Process Injection Decete

AgentSmith-HIDS可以实现实时监测进程注入的行为,使用过Hook sys_ptrace()来实现的,我们仅会采集**PTRACE_POKETEXT和PTRACE_POKEDATA**



### AntiRootkit(Beta Feature)

目前AgentSmith-HIDS支持对 execve/accept/accept4/connect 的进程/可执行文件做检测,可以有效的发现试图隐藏自己行踪的行为.

相关字段在hook execve/accept/accept4/connect 的信息中的**pid_rootkit_check**/**file_rootkit_check**,0代表异常.




### 自定义检测模块

1. 自定义检测模块依赖心跳检测模块，既需要开启心跳检测才可支持自定义检测模块；
2. 自定义检测模块的触发方式是心跳Server向Agent下发指令完成的，检测结果通过Kafka传递到Server端，因此不具备实时性；
3. 自定义检测函数添加在https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/agent/src/lib/detection_module.rs 文件下，并且需要在该文件的Detective impl的start函数定义好Mapping关系(Server下发指令和调用的检测函数关系)；
4. 添加完自定义检测函数后需要在https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/smith_console/heartbeat_server.py 中添加下发指令逻辑，注意需要和其他指令通过“;”间隔；
5. 实现逻辑，Agent向心跳服务器发送心跳包，Server返回检测指令，Agent通过指令和检测函数的Mapping执行指令所指的检测函数，检测结果通过Kafka传递到Server端。



### 快速测试 （您可以参考[Quick-Start](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/Quick-Start.md)中更为详细的说明）

1. 编译LKM，自己编译LKM需要安装Linux Kernel Source，编译目录在：`/syshook/LKM`，通过`make`得到`syshook.ko`LKM文件。
2. 下发编译好的LKM文件到测试服务器，注意Kernel版本需要和编译服务器保持一致。
3. 在测试环境安装LKM文件，`insmod syshook.ko`即可。
4. 部署测试环境接收端Kafka Server，注意需要手动创建topic。
5. (可选)部署测试环境HIDS心跳Server，具体请看：https://github.com/DianrongSecurity/AgentSmith-HIDS/tree/master/smith_console 。
6. 编译agent模块，需要提前安装rust环境。在目录：`/root/smithhids/agent/src/conf`下，先修改agent配置文件：`/root/smithhids/agent/src/conf/settings.rs`，修改相关的Kafka信息和心跳配置，通过`cargo build —-release`，在`/agent/target/release/ `下得到编译好的agent。(注：需要提前`yum install openssl` && `yum install openssl-devel`)
7. 安装agent，下发agent到测试环境，直接执行即可。
8. 如果配置并部署了HIDS心跳Server，可以通过HIDS Console来简单对测试服务器的情况进行查看，具体操作请看：https://github.com/DianrongSecurity/AgentSmith-HIDS/tree/master/smith_console 。
9. SELinux设置enforcing也不影响Agent运行。

（注：由于Agent取本机IP是通过命令:`hostname -i`，所以测试时请保证hostname和hosts配置正确，否则HIDS Console端无法读取正确的IP。）




### 整体流程图

![simple_flow_chart](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/simple_flow_chart.png)




### 卸载

卸载AgentSmith-HIDS前需要先关闭用户态agent进程，agent默认Log path：`/var/log/smith.log`，默认pid file：`/run/smith.pid`，默认下：`cat /run/smith.pid |xargs kill -9`再通过`rmmod syshook`来完成卸载。




### 简单演示

![Demo](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/demo.gif)




### Smith LKM define定义说明

| define                      | 说明                                                         |
| --------------------------- | ------------------------------------------------------------ |
| SEND_TYPE                   | LKM传输到用户态方案：<br />1:NETLINK;<br />2:SHERE_MEM；<br />默认：2 |
| HOOK_EXECVE                 | execve() hook 开关:<br />1:开启; <br />默认:  1              |
| HOOK_CONNECT                | connect() hook 开关:<br />1:开启; <br />默认:  1             |
| HOOK_PTRACE                 | 检测进程注入 开关:<br />1:开启; <br />默认:  1               |
| HOOK_ACCEPT                 | accept()/accept4() hook 开关:<br />1:开启; <br />默认:  0    |
| HOOK_INIT_MODULE            | init_module() hook 开关:<br />1:开启; <br />默认:  1         |
| HOOK_FINIT_MODULE           | finit_module() hook 开关:<br />1:开启; <br />默认:  1        |
| ROOTKIT_CHECK               | execve/accept/accept4/connect rootkit检测开关:<br />1:开启;<br />默认: 0 |
| KERNEL_PRINT                | debug输出：<br />-1:不输出;<br />1:输出共享内存时index信息;<br />2:输出捕获到的信息；<br />默认：-1 |
| DELAY_TEST                  | 测试传输方案延迟：<br />-1:关闭;<br />1:开启；<br />默认：-1 |
| WRITE_INDEX_TRY_LOCK        | 仅在SEND_TYPE=2时有意义，是控制对write_index lock方式：<br />-1:使用write_lock();<br />1:使用write_trylock()；<br />默认：-1 |
| WRITE_INDEX_TRY_LOCK_NUM    | 仅在WRITE_INDEX_TRY_LOCK=1时有意义，设置write_trylock()次数，默认：3 |
| CONNECT_TIME_TEST           | 测试connect()耗时：<br />0:关闭测试;<br />1:测试无Hook情况下耗时;<br />2:测试Hook情况下的耗时;<br />默认：0 |
| EXECVE_TIME_TEST            | 测试Hook execve()耗时:-<br />1:关闭;<br />1:开启;<br />默认：-1 |
| SAFE_EXIT                   | 安全rmmod：<br />-1:关闭，不会阻止rmmod，但是特殊情况会导致crash kernel;<br />1:开启，在会导致crash kernel的情况下会阻止rmmod;<br />默认：1 |
| MAX_SIZE                    | 仅在SEND_TYPE=2时有意义，表示与用户态共享内存大小，需要是整页数，默认：2097152（2M），用户态程序需一致 |
| CHECK_READ_INDEX_THRESHOLD  | 仅在SEND_TYPE=2时有意义，表示检测read_index的阈值，小于该阈值LKM将会丢弃捕获到的数据，默认：524288 |
| CHECK_WRITE_INDEX_THRESHOLD | 仅在SEND_TYPE=2时有意义，表示检测write_index距离共享内存区域边界阈值，超过阈值将会重置write_index，默认：32768 |
| DATA_ALIGMENT               | 尝试对需要传输的数据进行4字节对齐：<br />-1:关闭;<br />1:开启;<br />默认：-1 |
| EXIT_PROTECT                | 阻止自身被rmmod：<br />-1:关闭;<br />1:开启;<br />默认：-1   |



关于HOOK_ACCEPT,开启后可能会有一定的性能影响(如:在负载较高的主机上安装agent,由于accept太过频繁导致网络IO负载较高),如果使用AgentSmith仅是作为安全需求使用,那么可以关闭该Hook.该HOOK在需要梳理网络通讯关系时可以开启,帮助分析资产间访问关系.

关于SAFE_EXIT，当在Hook connect情况下，如果在rmmod时有connect还未返回，那么rmmod后connect将会返回到错误的内存地址上，将会引起kernel crash。开启SAFE_EXIT会通过增加引用的方式来阻止这种情况的发生，但是可能会导致无法立即rmmod LKM。如果关闭SAFE_EXIT，需要注意如果想卸载Smith LKM需要通过重启的方式，否则可能会造成生产事故。

其实Smith LKM在没有用户态读取数据的情况下会自动关闭其几乎全部功能，对性能影响几乎可以无视。




### 特别说明

* 虽然我们通过Hook syscall来尽可能的拿到所有我们想要的信息，但是需要注意依然存在绕过Hook的可能性，虽然这种情况难度较大，可能性很小。我们建议如果想要确保万无一失，在服务器初始化后尽早的部署HIDS。

* 请在使用前进行充分测试。



### 关于项目进度和未来

AgentSmith-HIDS 目前已经在点融经过压力测试/稳定性测试，目前正在内部线上测试环境进行更加全面的测试。

(本人已从点融离职，目前就职于一家游戏公司，稳定性测试依然在进行)

未来计划：

- 持续稳定性/性能测试。
- 对Connect行为后续传输的数据进行偏移量计算从而得到一些关键信息(部分协议，如HTTP)，如Host这样的信息。
- 借鉴LKRG，对Kernel进行保护。
- 增加Rootkit的Connect行为实时检测。




### 致谢

感谢[@yuzunzhi](https://github.com/yuzunzhi)和[@hapood](https://github.com/hapood)在项目过程中的大力支持！！！



### 作者微信

<img src="./wechat.jpg" width="50%" height="50%"/>


## License

AgentSmith-HIDS kernel module are distributed under the GNU GPLv2 license.
