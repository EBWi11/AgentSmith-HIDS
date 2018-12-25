use std::io::prelude::*;
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time;

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

    pub fn run(self) {
        loop {
            match TcpStream::connect(self.server.clone()) {
                Err(e) => {
                    println!("CONNECT_HEARTBEAT_ERROR:{}", e);
                }
                Ok(mut stream) => {
                    let tmp_res = &stream.write(self.msg.as_bytes());
                    match tmp_res {
                        Ok(_) => {}
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