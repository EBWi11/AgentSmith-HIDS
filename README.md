# AgentSmith-HIDS

A project which is named by inspiration from the movie ---The Matrix



[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/LICENSE)


English | [简体中文](README-zh_CN.md)




### About AgentSmith-HIDS

The AgentSmith-HIDS is not strictly a "Host-based Intrusion Detection System" due to absence of the rule engine and related detection functions in open sourced part, but it can be used as a high-performance "host intelligence collection tool" in building your own HIDS.




### Who will be interested in AgentSmith-HIDS？

For security engineers who have a certain understanding of Linux and need a functional HIDS, yet are not satisfied with the performance, collaboration capacity or secondary development difficulty of existing HIDS, the AgentSmith-HIDS may be your choice. The AgentSmith-HIDS is developed for collaboration with Dianrong’s AgentSmith-NIDS, focusing on lower performance loss and higher collaboration capacity.




### What does the AgentSmith-HIDS achieved:
* Hook the system_call of **execve, connect,accept,accept4, init_module, finit_module** by loading LKM;

* Being compatible with Linux namespace so that information of Docker container can be collected;

* Implemented two ways of transferring Hook Info from kernel mode to user mode: netlink and shared memory. The transmission loss under shared memory mode is 30% less compared to netlink with a time-consuming median of 8478ns on test server. Please refer to https://github.com/DianrongSecurity/AgentSmith-HIDS/tree/master/doc for detailed AgentSmith-HIDS BencherMark.



### About compatible systems and kernel versions

* AgentSmith-HIDS has only been fully tested on Centos version 6/7 and Kernel version 2.6.32/3.10. Anyone who have tested the compatibility on other versions, Feel is always welcome and please do feel free to contact us (a stability test report will be required)
* We will keep the development of the AgentSmith-HIDS and following the latest release of stable version of Centos7.
* Real-time Porcess Inject Detect
* Real-time Rootkit Detect(Beta Feature)



### About compatibility with Docker

Installing the AgentSmith-HIDS on the host enables you to monitor the behavior of the container on corresponding host. The nodename varies depends on the source of the behavior, which should be:

| Source of the behavior  | Nodename       |
| ----------------------- | -------------- |
| Host                    | hostname       |
| Native Docker container | container name |
| k8s                     | pod name       |



### How to use the AgentSmith-HIDS
* The AgentSmith-HIDS provides a simple user-mode demo which is responsible for receiving information transmitted from LKM, converting the information received to JSON format and forwarding it to the server. We utilized the Rust in developing the AgentSmith-HIDS and the openssl lib will be required to provide necessary support. Also, the transmission method is Kafka.
* The positioning of the AgentSmith-HIDS is a lightweight, high-performance information collecting tool, which can further detect some blind spots in the detection capability of the AgentSmith-NIDS such as shell reversion, command execution, malicious programs downloading, some rootkits etc... Meanwhile, it collaborates with the AgentSmith-NIDS and CMDB to provide a comprehensive view including:<br>
	•	PID;<br>
	•	PPID;<br>
	•	Nodename;<br>
	•	Cmdline;<br>
	•	Cwd;<br>
	•	User;<br>
	•	Exe;<br>
	•	TCP/UDP quintuple;<br>
	•	Raw data of some supported protocals;<br>
	•	Related business information;<br>
	•	FW_RULE;<br>
	•	NIDS/HIDS rules;<br>
	•	threat intelligence information.<br>



### About the current progress and future plan
AgentSmith-HIDS has passed stress testing/stability testing in Dianrong, and is currently conducting more comprehensive testing in the internal online test environment. The Linux baseline check/Linux integrity check function will be updated in the future.




### Rapid Testing （You can refer to [Quick-Start](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/Quick-Start.md) for a detailed version）
1. Compile LKM, To compile LKM yourself, you need to install Linux Kernel Source. The directory will be: `/syshook/LKM` and get the LKM file `syshook.ko` by `make`.

2. Publish the compiled LKM file to your test server. Please pay attention that the Kernel version needs to be consistent with the server used for compiling.

3. Install the LKM file in the test environment by using `insmod syshook.ko`

4. Deploy the Kafka Server in your test environment for receiving information and create topic manually.

5. (Optional) Deploy a Heartbeat Server in your test environment, please refer to: https://github.com/DianrongSecurity/AgentSmith-HIDS/tree/master/smith_console

6. In order to compile the agent module, you need to install the rust environment in advance. In the directory: `/root/smithhids/agent/src/conf`, modify the related Kafka information and heartbeat configuration in configuration file of the agent: `/root/smithhids/agent/src/conf/settings.rs`, then run `cargo build --release`, on `/agent/target/release/` can get agent.（maybe need `yum install openssl` && `yum install openssl-devel`)

7. Install the agent: deploy the agent to your test environment and execute it directly.

8. If the Heartbeat Server is configured and deployed, you will be able to review the status of the test server through the HIDS Console. For details, please refer to: https://github.com/DianrongSecurity/AgentSmith-HIDS/tree/master/smith_console.

9. Enforcing configured to SELinux will not affect the agent.

Note: Since the Agent obtains the local IP through the command: `hostname -i`, please ensure that the hostname and hosts are configured correctly during the test to prevent the HIDS Console from getting a wrong one.



### AntiRootkit(Beta Feature)

AgentSmith-HIDS will decete execve/accept/accept4/connect call's PID/ELF File,can find most rootkit action.

Detection info field(execve/accept/accept4/connect): **pid_rootkit_check**//**file_rootkit_check**,0 is abnormal.  




### Work Flow Chart

![simple_flow_chart](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/simple_flow_chart.png)




### Uninstalling

Before uninstalling the AgentSmith-HIDS, you need to close the user-mode agent process. The default Log path of the agent is located in: `/var/log/smith.log`, and also the default pid file in: `/run/smith.pid`. By default: `cat /run/ Smith.pid |xargs kill -9` then uninstall it by `rmmod syshook`.




### Simple Demo

![Demo](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/demo.gif)




### Smith LKM Definition


| Define                      | Description                                                  |
| --------------------------- | ------------------------------------------------------------ |
| SEND_TYPE                   | LKM to user mode transmission method: <br />1. NETLINK; <br />2. SHERE_MEM;<br /> Default: 2 |
| HOOK_EXECVE                 | execve() Hook Switch:<br />1. Enable;<br />Default:1         |
| HOOK_CONNECT                | connect() Hook Switch:<br />1. Enable;<br />Default:1        |
| HOOK_PTRACE                 | Porcess Inject Detect Switch:<br />1. Enable;<br />Default:1 |
| HOOK_ACCEPT                 | accept() Hook Switch:<br />1. Enable;<br />Default:0         |
| HOOK_INIT_MODULE            | init_module() Hook Switch:<br />1. Enable;<br />Default:1    |
| HOOK_FINIT_MODULE           | finit_module() Hook Switch:<br />1. Enable;<br />Default:1   |
| ROOTKIT_CHECK               | execve;accept;accept4;connect Rootkit Detect Swith:<br />1. Enable;<br />Default:0 |
| KERNEL_PRINT                | Debug output:<br />-1. no output;<br />1. index information in shared memory;<br />2. captured information;<br />Default: -1 |
| DELAY_TEST                  | Delay during transmission:<br />-1. Disable<br />1. Enable<br />Default: -1 |
| WRITE_INDEX_TRY_LOCK        | Only functional when SEND_TYPE=2, which controls the method of write_index lock:<br />-1. Use write_lock()<br />1. Use write_trylock()<br />Default: -1 |
| WRITE_INDEX_TRY_LOCK_NUM    | Only functional when WRITE_INDEX_TRY_LOCK=1, which sets the number of write_trylock()<br />Default: 3 |
| CONNECT_TIME_TEST           | Test time consuming of connect():<br />0.Disable<br />1.Test time consuming of connect() without Hook<br />2.Test time consuming of connect() with Hook<br />Default: 0 |
| EXECVE_TIME_TEST            | Test time consuming of Hook execve():<br />-1.Disable;<br />1.Enable;<br />Default: -1 |
| SAFE_EXIT                   | Safe rmmod:<br />-1.Disable, which will not stop rmmod, may leads to kernel crashed under some special circumstances;<br />1.Enable, which will stop rmmod when it may cause kernel crashed;<br />Default: 1 |
| MAX_SIZE                    | Only functional when SEND_TYPE=2, which defines the the size of memory shared with the user mode. Must be consistent with the configuration in user mode and should be set to use whole pages.<br />Default: 2097152 (2M). |
| CHECK_READ_INDEX_THRESHOLD  | Only functional when SEND_TYPE=2, which means the threshold of read_index. Any data captured by LKM and the size is less than the threshold will be discarded.<br />Default: 524288 |
| CHECK_WRITE_INDEX_THRESHOLD | Only functional when SEND_TYPE=2, which means the threshold of write_index from boundary of the shared memory. The write_index will be reset when it exceeds the threshold.<br />Default: 32768 |
| DATA_ALIGMENT               | Try 4-byte alignment of the data that needs to be transferred:<br />-1.off;<br />1.on;<br />Default: -1 |
| EXIT_PROTECT                | Protect the agent itself from being rmmod:<br />1.Disable;<br />2.Enable;<br />Default: -1 |




About SAFE_EXIT: in the case of Hook connect, if there is a connection not returned when executing rmmod, then connect will return to a wrong memory address after rmmod, which will lead to kernel crashed. Enable the SAFE_EXIT will prevent this from happening by adding references, and as consequences, the rmmod LKM may not be execute immediately. If the SAFE_EXIT is disabled, it is necessary to note that if you want to uninstall Smith LKM, a restart to the host is needed. Otherwise, it may cause an incident to your host or running programs.

In fact, Smith LKM will automatically turn off almost all of its functions without data access from user-mode, thus the impact to performance of the host can be ignored.




### Special Note

* Although we have collected all the information we want through Hook syscall, there is still possibility of bypassing Hook which you may want to pay attention to, even it is pretty difficult and not likely to happen a lot. We recommend that you should deploy HIDS as soon as possible after the server is initialized to achieve a better protection.

* Please perform comprehensive testing work before deploy the HIDS.



### Special Thanks

Credits to [@yuzunzhi](https://github.com/yuzunzhi) and [@hapood](https://github.com/hapood) and thank you for all the support provided during our development.


### Author WeChat

<img src="./wechat.jpg" width="50%" height="50%"/>


## License

AgentSmith-HIDS kernel module are distributed under the GNU GPLv2 license.

