use std::io::prelude::*;
use std::time::Duration;
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use lib::kafka_output::KafkaOutput;
use lib::detection_module::Detective;

pub struct HeartBeat {
    server: String,
    msg: String,
}

fn get_output_kafka(threads: u32) -> KafkaOutput {
    KafkaOutput::new(threads,true)
}

impl HeartBeat {
    pub fn new(server: String, msg: String) -> HeartBeat {
        HeartBeat {
            server: server.clone(),
            msg: msg,
        }
    }

    pub fn run(self) {
        let (tx, rx) = channel();
        let arx = Arc::new(Mutex::new(rx));
        let output = get_output_kafka(1);
        output.start(arx);

        loop {
            match TcpStream::connect(self.server.clone()) {

                Err(e) => {
                    println!("CONNECT_HEARTBEAT_ERROR:{}", e);
                }

                Ok(mut stream) => {
                    let tmp_res = &stream.write(self.msg.as_bytes());
                    match tmp_res {
                        Ok(_) => {
                            stream.set_read_timeout(Some(Duration::new(5, 0))).expect("set_read_timeout call failed");
                            let mut buffer = String::new();
                            stream.read_to_string(&mut buffer).unwrap();
                            if buffer.trim().len() > 3 {
                                let res_list = Detective::start(buffer.trim().to_string());
                                for i in res_list {
                                    tx.send(i.as_bytes().to_vec()).expect("SEND_MSG_TO_KAFKA_ERROR(Detective)");
                                }
                            }
                        }
                        Err(e) => {
                            println!("SEND_HEARTBEAT_ERROR:{}", e);
                        }
                    }
                    let _ = stream.shutdown(Shutdown::Both);
                }

            }

            thread::sleep(time::Duration::from_secs(30));
        }
    }
}