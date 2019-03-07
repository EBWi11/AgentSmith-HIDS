pub const HEARTBEAT_SERVER: &str = "10.18.18.18:5157";
pub const HEARTBEAT: bool = true;

pub const SEND_KAFKA_FAST_TYPE : bool = false;

pub const DAEMON: bool = true;
pub const PID_FILE_PATH: &str = "/run/smith.pid";
pub const SMITH_LOG_FILE: &str = "/var/log/smith.log";

pub const DEFAULT_KAFKA_THREADS: u32 = 5;
pub const BROKER: &str = "10.18.18.18:9092";
pub const TOPIC: &str = "hids";
pub const COALESCE: usize = 2;
pub const COMPRESSION: &'static str = "snappy";