pub const HEARTBEAT_SERVER: &str = "192.168.165.153:5157";
pub const HEARTBEAT: bool = true;
pub const AUTO_INSTALL_LKM: bool = false;

pub const SEND_KAFKA_FAST_TYPE : bool = false;

pub const DAEMON: bool = true;
pub const PID_FILE_PATH: &str = "/var/run/smith_hids.pid";
pub const SMITH_LOG_FILE: &str = "/var/log/smith_hids.log";
pub const LKM_SERVER: &str = "http://10.18.18.18/";
pub const LKM_TMP_PATH: &str = "/tmp/YWdlbnRzbWl0aGJ5ZWJ3aWxs";

pub const DEFAULT_KAFKA_THREADS: u32 = 2;
//pub const BROKER: &str = "127.0.0.1:9092";
pub const BROKER: &str = "secmq1.uuzu.com:9092,secmq2.uuzu.com:9092,secmq3.uuzu.com:9092,secmq4.uuzu.com:9092";
pub const TOPIC: &str = "hids";
pub const COALESCE: usize = 3;
pub const COMPRESSION: &'static str = "none";