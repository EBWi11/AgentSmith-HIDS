# AgentSmith-HIDS

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;--项目名称灵感来源于电影《黑客帝国》



[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/LICENSE) [![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[English](README.md) | 简体中文




### 关于AgentSmith-HIDS

AgentSmith-HIDS严格意义上并不是一个“Host-based Intrusion Detection System”，因为目前开源的部分来讲它缺乏了规则引擎和相关检测的能力，但是它可以作为一个高性能“主机信息收集工具”来构建属于你自己的HIDS。
由于AgentSmit-HIDS的特点(**从内核态获取尽可能全的数据**)，对比用户态的HIDS拥有巨大的优势：

* **性能更优**，通过内核态驱动来获取信息，无需诸如遍历/proc这样的行为进行数据补全；传输方案使用共享内存，而不是netlink，相对来说也有更好的性能表现。
* **难以绕过**，由于我们的信息获取是来自于内核态驱动，因此面对很多刻意隐藏自己的行为如rootkit难以绕过我们的监控。
* **为联动而生**，我们不仅可以作为安全工具，也可以作为监控，或者梳理内部资产。我们通过内核模块对进程/用户/文件/网络连接进行梳理，如果有CMDB的信息，那么联动后你将会得到一张从网络到主机/容器/业务信息的调用/依赖关系图；如果你们还有DB Audit Tool，那么联动后你可以得到DB User/库表字段/应用/网络/主机容器的关系；等等，还可以和NIDS/威胁情报联动，达到溯源的目的。
* **用户态+内核态**，AgentSmith-HIDS同时拥有内核态和用户态的模块，可以形成互补。



### AgentSmith-HIDS实现了以下的主要功能：

* 内核模块通过kprobeHook了**execve,connect,process inject, mprotect, create file,DNS query,load LKM**的行为，并且通过对Linux namespace兼容的方式实现了对容器行为的信息收集
* 用户态支持自定义检测模块，目前已内置：**系统用户列表查询**，**系统端口监听列表查询**，**系统RPM LIST查询**，**系统定时任务查询**
* **部分Rootkit检测能力**，From: [Tyton](https://github.com/nbulischeck/tyton) ，目前已经移植了**PROC_FILE_HOOK**，**SYSCALL_HOOK**，**LKM_HIDDEN**，**INTERRUPTS_HOOK**，目前仅支持Kernel > 3.10。
* cred 变化检测 （sudo/su/sshd除外）
* 用户登陆监控


### AgentSmith-HIDS的使用场景/方式(待补充)

* [如何利用AgentSmith-HIDS检测反弹shell](doc/How-to-use-AgentSmith-HIDS-to-detect-reverse-shell/如何利用AgentSmith-HIDS检测反弹shell.md)



### 关于内核版本兼容性

* Kernel > 2.6.25
* AntiRootKit > 3.10



### 对容器的兼容

| 行为源 | Nodename       |
| ------ | -------------- |
| Host   | hostname       |
| Docker | container name |
| k8s    | pod name       |




### AgentSmith-HIDS的组成部分

* **内核驱动模块（LKM）**，通过kprobe hook关键函数，进行数据捕获；
* **用户态Agent**，收取驱动捕获的指令并进行处理，然后将数据发送到Kafka；并向Server发送心跳确认存活，以及接受Server下发的指令进行执行；
* **Agent Server端**，向Agent下发指令，以及来查看当前Agent状态数量等信息；（可选组件）



### Execve Hook

通过Hook **sys_execve()/sys_execveat()/compat_sys_execve()/compat_sys_execveat()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"59",
    "run_path":"/opt/ltp/testcases/bin/growfiles",
    "exe":"/opt/ltp/testcases/bin/growfiles",
    "argv":"growfiles -W gf26 -D 0 -b -i 0 -L 60 -u -B 1000b -e 1 -r 128-32768:128 -R 512-64000 -T 4 -f gfsmallio-35861 -d /tmp/ltp-Ujxl8kKsKY ",
    "pid":"35861",
    "ppid":"35711",
    "pgid":"35861",
    "tgid":"35861",
    "comm":"growfiles",
    "nodename":"test",
    "stdin":"/dev/pts/1",
    "stdout":"/dev/pts/1",
    "sessionid":"3",
    "dip":"192.168.165.1",
    "dport":"61726",
    "sip":"192.168.165.128",
    "sport":"22",
    "sa_family":"1",
    "pid_tree":"1(systemd)->1384(sshd)->2175(sshd)->2177(bash)->2193(fish)->35552(runltp)->35711(ltp-pan)->35861(growfiles)",
    "tty_name":"pts1",
    "socket_process_pid":"2175",
    "socket_process_exe":"/usr/sbin/sshd",
    "SSH_CONNECTION":"192.168.165.1 61726 192.168.165.128 22",
    "LD_PRELOAD":"/root/ldpreload/test.so",
    "user":"root",
    "time":"1579575429143",
    "local_ip":"192.168.165.128",
    "hostname":"test",
    "exe_md5":"01272152d4901fd3c2efacab5c0e38e5",
    "socket_process_exe_md5":"686cd72b4339da33bfb6fe8fb94a301f"
}
```



### Connect Hook

通过Hook **sys_connect()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"42",
    "sa_family":"2",
    "fd":"4",
    "dport":"1025",
    "dip":"180.101.49.11",
    "exe":"/usr/bin/ping",
    "pid":"6294",
    "ppid":"1941",
    "pgid":"6294",
    "tgid":"6294",
    "comm":"ping",
    "nodename":"test",
    "sip":"192.168.165.153",
    "sport":"45524",
    "res":"0",
    "sessionid":"1",
    "user":"root",
    "time":"1575721921240",
    "local_ip":"192.168.165.153",
    "hostname":"test",
    "exe_md5":"735ae70b4ceb8707acc40bc5a3d06e04"
}
```



### DNS Query Hook

通过Hook **sys_recvfrom()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"601",
    "sa_family":"2",
    "fd":"4",
    "dport":"53",
    "dip":"192.168.165.2",
    "exe":"/usr/bin/ping",
    "pid":"6294",
    "ppid":"1941",
    "pgid":"6294",
    "tgid":"6294",
    "comm":"ping",
    "nodename":"test",
    "sip":"192.168.165.153",
    "sport":"53178",
    "qr":"1",
    "opcode":"0",
    "rcode":"0",
    "query":"www.baidu.com",
    "sessionid":"1",
    "user":"root",
    "time":"1575721921240",
    "local_ip":"192.168.165.153",
    "hostname":"test",
    "exe_md5":"39c45487a85e26ce5755a893f7e88293"
}
```

### mprotect Hook

通过Hook **mprotect()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"10",
    "exe":"/root/dlinject/main",
    "pid":"9729",
    "ppid":"2443",
    "pgid":"9729",
    "tgid":"9729",
    "comm":"main",
    "start":"140377101094912",
    "len":"16384",
    "prot":"1",
    "nodename":"test",
    "sessionid":"4",
    "user":"root",
    "time":"1582823732418",
    "local_ip":"192.168.165.152",
    "hostname":"test",
    "exe_md5":"716d8dc1f34427ed1893dc9958e96b2f"
}

```

### Create File Hook

通过Hook **security_inode_create()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"602",
    "exe":"/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.232.b09-0.el7_7.x86_64/jre/bin/java",
    "file_path":"/tmp/kafka-logs/replication-offset-checkpoint.tmp",
    "pid":"3341",
    "ppid":"1",
    "pgid":"2657",
    "tgid":"2659",
    "comm":"kafka-scheduler",
    "nodename":"test",
    "sessionid":"3",
    "user":"root",
    "time":"1575721984257",
    "local_ip":"192.168.165.153",
    "hostname":"test",
    "exe_md5":"215be70a38c3a2e14e09d637c85d5311",
    "create_file_md5":"d41d8cd98f00b204e9800998ecf8427e"
}
```



### Process Inject Hook

通过Hook **sys_ptrace()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"101",
    "ptrace_request":"4",
    "target_pid":"7402",
    "addr":"00007ffe13011ee6",
    "data":"-a",
    "exe":"/root/ptrace/ptrace",
    "pid":"7401",
    "ppid":"1941",
    "pgid":"7401",
    "tgid":"7401",
    "comm":"ptrace",
    "nodename":"test",
    "sessionid":"1",
    "user":"root",
    "time":"1575722717065",
    "local_ip":"192.168.165.153",
    "hostname":"test",
    "exe_md5":"863293f9fcf1af7afe5797a4b6b7aa0a"
}
```


### Load LKM File Hook

通过Hook **load_module()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"603",
    "exe":"/usr/bin/kmod",
    "lkm_file":"/root/ptrace/ptrace",
    "pid":"29461",
    "ppid":"9766",
    "pgid":"29461",
    "tgid":"29461",
    "comm":"insmod",
    "nodename":"test",
    "sessionid":"13",
    "user":"root",
    "time":"1577212873791",
    "local_ip":"192.168.165.152",
    "hostname":"test",
    "exe_md5":"0010433ab9105d666b044779f36d6d1e",
    "load_file_md5":"863293f9fcf1af7afe5797a4b6b7aa0a"
}
```


### Cred Change Hook

通过Hook **commit_creds()** 实现，数据样例：

```json
{
    "uid":"0",
    "data_type":"604",
    "exe":"/tmp/tt",
    "pid":"27737",
    "ppid":"26865",
    "pgid":"27737",
    "tgid":"27737",
    "comm":"tt",
    "old_uid":"1000",
    "nodename":"test",
    "sessionid":"42",
    "user":"root",
    "time":"1578396197131",
    "local_ip":"192.168.165.152",
    "hostname":"test",
    "exe_md5":"d99a695d2dc4b5099383f30964689c55"
}
```


### User Login Alert
```json
{
    "data_type":"1001",
    "status":"Failed",
    "type":"password",
    "user_exsit":"false",
    "user":"sad",
    "from_ip":"192.168.165.1",
    "port":"63089",
    "processor":"ssh2",
    "time":"1578405483119",
    "local_ip":"192.168.165.128",
    "hostname":"localhost.localdomain"
}
```


### PROC File Hook Alert
```json
{
    "uid":"-1",
    "data_type":"700",
    "module_name":"autoipv6",
    "hidden":"0",
    "time":"1578384987766",
    "local_ip":"192.168.165.152",
    "hostname":"test"
}
```


### Syscall Hook Alert
```json
{
    "uid":"-1",
    "data_type":"701",
    "module_name":"diamorphine",
    "hidden":"1",
    "syscall_number":"78",
    "time":"1578384927606",
    "local_ip":"192.168.165.152",
    "hostname":"test"
}
```


### LKM Hidden Alert
```json
{
    "uid":"-1",
    "data_type":"702",
    "module_name":"diamorphine",
    "hidden":"1",
    "time":"1578384927606",
    "local_ip":"192.168.165.152",
    "hostname":"test"
}
```


### Interrupts Hook Alert
```json
{
    "uid":"-1",
    "data_type":"703",
    "module_name":"syshook",
    "hidden":"1",
    "interrupt_number":"2",
    "time":"1578384927606",
    "local_ip":"192.168.165.152",
    "hostname":"test"
}
```


### 关于性能

测试环境：

| CPU       | Intel(R) Core(TM) i7-4870HQ CPU @ 2.50GHz    2核 |
| --------- | ------------------------------------------------ |
| RAM       | 2GB                                              |
| OS/Kernel | Centos7  /  3.10.0-1062.7.1.el7.x86_64           |

测试结果：

| Hook Handler           | Average Delay(us) |
| ---------------------- | ----------------- |
| execve_entry_handler   | 10.4              |
| connect_handler        | 7.5               |
| connect_entry_handler  | 0.06              |
| recvfrom_handler       | 9.2               |
| recvfrom_entry_handler | 0.17              |
| fsnotify_post_handler  | 0.07              |

原始测试数据：

[Benchmark Data](https://github.com/EBWi11/AgentSmith-HIDS/tree/master/benchmark_data)



### 部署及测试文档

[Quick Start](https://github.com/EBWi11/AgentSmith-HIDS/blob/master/doc/AgentSmith-HIDS-Quick-Start-zh_CN.md)




### 致谢(排名不分先后)

[yuzunzhi](https://github.com/yuzunzhi)

[hapood](https://github.com/hapood)

[HF-Daniel](https://github.com/HF-Daniel)




### 作者微信

<img src="doc/wechat.jpg" width="50%" height="50%"/>


### 灾难控制局微信公众号

会时不时有一些AgentSmith-HIDS的更新介绍和能力详解，有兴趣的可以关注：

<img src="doc/SecDamageControl.jpg" width="50%" height="50%"/>


## License

AgentSmith-HIDS kernel module are distributed under the GNU GPLv2 license.
