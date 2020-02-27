# AgentSmith-HIDS Quick Start

English | [简体中文](AgentSmith-HIDS-Quick-Start-zh_CN.md)


### 1.AgentSmith-HIDS Work Flow Chart

![simple_flow_chart](simple_flow_chart.png)



### 2.Get Clone Project

`git clone https://github.com/EBWi11/AgentSmith-HIDS.git`



### 3.Compile LKM,Get 'smith.ko' File

* `yum` or `apt` or other package tools install `kernel-devel` && `kernel-header`
* go to directory:`driver/LKM` and execute `make`,you can get 'smith.ko' file
* execute `insmod smith.ko`
* execute `lsmod | grep smitm`,verify load lkm is success
* publish the compiled LKM file(smith.ko) to your test server. Please pay attention that the Kernel version needs to be consistent with the server used for compiling

![quick-start-01](quick-start-01.png)



### 4.Test 'smith.ko'

* `yum` or `apt` or other package tools install `gcc`
* go to directory:`driver/test` and execute `gcc -o test shm_user.c`,you can get 'test'
* execute `./test`,verify core is work

![quick-start-02](quick-start-02.png)



### 5.Deploy the Kafka Server && Agent Server(Optional)

* in your test environment for receiving information and create topic manually:
  like this `./kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic hids`

* (Optional) deploy a heartbeat server in your test environment,please refer to:[smith_console](https://github.com/EBWi11/AgentSmith-HIDS/tree/master/smith_console)



### 6.Compile User Space Module

* need intall rust environment: https://www.rust-lang.org/tools/install

* go to directory:`agent/src/conf` and modify the related Kafka information and heartbeat configuration in configuration file of the agent: `agent/src/conf/settings.rs`, then run `cargo build --release`, on `agent/target/release/` can get agent.（maybe need `install openssl` && `install openssl-devel`)

* Install the agent: deploy the agent to your test environment and execute it directly

Note: Since the Agent obtains the local IP through the command: hostname -i, please ensure that the hostname and hosts are configured correctly during the test to prevent the HIDS Console from getting a wrong one.

![quick-start-03](quick-start-03.png)



### 7.Custom detection module

1. The custom detection module relies on the heartbeat detection module. You need to enable heartbeat detection to support the custom detection module;
2. The triggering method of the custom detection module is completed by the heartbeat server sending instructions to the agent, and the detection result is transmitted to the server through Kafka, so it is not real-time;
3. The custom detection function is added in the [detection_module.rs](https://github.com/EBWi11/AgentSmith-HIDS/blob/master/agent/src/lib/detection_module.rs) file, and the start function definition of the Detective impl in this file needs Good mapping relationship (the relationship between the instruction issued by the server and the detection function called);
4. After adding the custom detection function, you need to add the issuing instruction logic in [heartbeat_server.py](https://github.com/EBWi11/AgentSmith-HIDS/blob/master/smith_console/heartbeat_server.py). Note that you need to pass ";" interval;
5. Implement the logic. The agent sends a heartbeat packet to the heartbeat server. The server returns the detection instruction. The agent executes the detection function indicated by the instruction through the mapping of the instruction and the detection function. The detection result is transmitted to the server through Kafka.



### 8.Uninstall
* Before uninstalling the AgentSmith-HIDS, you need to close the user-mode agent process. The default Log path of the agent is located in: `/var/log/smith_hids.log`, and also the default pid file in: `/var/run/smith_hids.pid`. By default: `cat /var/run/smith_hids.pid |xargs kill -9` then uninstall it by `rmmod smith`




### 9.Smith LKM Definition

| Define           | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| EXECVE_HOOK      | execve() Hook Switch:<br />1. Enable;<br />Default:1         |
| CONNECT_HOOK     | connect() Hook Switch:<br />1. Enable;<br />Default:1        |
| DNS_HOOK         | DNS Hook Switch:<br />1. Enable;<br />Default:1              |
| MPROTECT_HOOK | Detect mprotect(PROT_READ or PROT_EXEC) in real time:<br />1.Enable;<br />Default: 0 |
| PTRACE_HOOK      | Porcess Injection Detect Hook Switch:<br />1. Enable;<br />Default:1 |
| CREATE_FILE_HOOK | Create File Detect Hook Switch:<br />1. Enable;<br />Default:1 |
| LOAD_MODULE_HOOK | init_module() Hook Switch:<br />1. Enable;<br />Default:1    |
| EXIT_PROTECT     | Protect the agent itself from being rmmod:<br />1.Enable;<br />Default: 0 |
| ROOTKIT_CHECK    | Regularly detect rootkit behavior. The default is 15 seconds:<br />1.Enable;<br />Default: 1 |
| UPDATE_CRED_HOOK | Detect abnormal process Cred changes in real time:<br />1.Enable;<br />Default: 1 |

### 10.Simple Demo

![Demo](demo.gif)

