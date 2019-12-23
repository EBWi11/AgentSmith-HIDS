use lib::detection_module::Detective;
use std::io::prelude::*;
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::Sender;
use std::thread;
use std::time;
use std::time::Duration;

pub struct HeartBeat {
    server: String,
    msg: String,
}

impl HeartBeat {
    pub fn new(server: String, msg: String) -> HeartBeat {
        HeartBeat {
            server: server.clone(),
            msg: msg,
        }
    }

    pub fn run(self, tx: Sender<Vec<u8>>) {
        loop {
            match TcpStream::connect(self.server.clone()) {
                Err(e) => {
                    println!("CONNECT_HEARTBEAT_ERROR:{}", e);
                }

                Ok(mut stream) => {
                    let tmp_res = &stream.write(self.msg.as_bytes());
                    match tmp_res {
                        Ok(_) => {
                            stream.set_read_timeout(Some(Duration::new(5, 0))).expect("READ_MSG_TIMEOUT");
                            let mut buffer = String::new();
                            stream.read_to_string(&mut buffer).unwrap();
                            if buffer.trim().len() > 3 {
                                let res_list = Detective::start(buffer.trim().to_string());
                                for i in res_list {
                                    tx.send(i.as_bytes().to_vec()).expect("READ_CMD_ERROR");
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

            thread::sleep(time::Duration::from_secs(15));
        }
    }
}