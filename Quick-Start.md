### 一、生成内核态agent（LKM模块）

1. clone项目到服务器

`git clone https://github.com/DianrongSecurity/AgentSmith-HIDS.git`

2. 安装Linux Kernal Source

`sudo yum install -y "kernel-devel-uname-r == $(uname -r)"`

3. 编译LKM文件（有告警，不影响）

`cd AgentSmith-HIDS/syshook/LKM`

`make`

4. 安装LKM文件

`insmod syshook.ko`

至此，内核态agent（LKM）已经制作完成，接下来可以测试一下

5. 测试

   5.1 进入test文件夹

   `cd AgentSmith-HIDS/syshook/test`

   5.2 修改一个小地方

   `vim shm_user.c`

   把文件末尾原来的shm_run_no_callback(); 替换为 printf("\n%s\n",shm_run_no_callback());  

   5.3 编译测试文件，生成a.out可执行测试文件

   `gcc -g shm_user.c`

   5.4 执行a.out可执行测试文件

   `nohup ./a.out &`

   5.5 查看结果（内核态的执行信息会打印到nohup.out文件中）

   `tail -f nohup.out`



### 二、准备kafka消息队列环境

1. 安装zookeeper
2. 安装kafka
3. 启动zookeeper（默认监听2181端口）

4. 启动kafka（默认监听9092端口）
5. 手动创建topic，HIDS_TEST

`cd “kafka安装路径”/bin`

`./kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic HIDS_TEST`



### 三、生成用户态Agent

1. 安全rust编译环境和包管理软件cargo

`yum install -y rust`

`yum install -y cargo`

2. 修改用户态agent配置文件

`vim AgentSmith-HIDS/agent/src/conf/settings.rs`

修改其中的kafka配置信息

```pub const BROKER: &str = "localhost:9092";
pub const TOPIC: &str = "hello_topic";
pub const BROKER: &str = "localhost:9092";
```

3. 在项目的agent目录下执行编译，生成target文件夹

`cd AgentSmith-HIDS/agent`

`cargo build --release`

4. 执行agent

`cd AgentSmith-HIDS/agent/target/release`

`./agent`

5. 在kafka消息队列中查看结果

`cd "kafka安装路径"/bin`

`./kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic HIDS_TEST`

