use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::SeekFrom;
use std::sync::mpsc::Sender;
use std::os::unix::fs::MetadataExt;
use std::thread::sleep;
use std::time::Duration;

pub struct LogWatcher {
    filename: String,
    inode: u64,
    pos: u64,
    reader: BufReader<File>,
    finish: bool,
    local_ip_str: String,
    hostname_str: String,
    tx: Sender<Vec<u8>>,
}

impl LogWatcher {
    pub fn register(filename: String, local_ip_str: String, hostname_str: String, tx: Sender<Vec<u8>>) -> Result<LogWatcher, io::Error> {
        let f = match File::open(filename.clone()) {
            Ok(x) => x,
            Err(err) => return Err(err),
        };

        let metadata = match f.metadata() {
            Ok(x) => x,
            Err(err) => return Err(err),
        };

        let mut reader = BufReader::new(f);
        let pos = metadata.len();
        reader.seek(SeekFrom::Start(pos)).unwrap();
        Ok(LogWatcher {
            filename: filename,
            inode: metadata.ino(),
            pos: pos,
            reader: reader,
            finish: false,
            local_ip_str: local_ip_str,
            hostname_str: hostname_str,
            tx: tx,
        })
    }

    fn reopen_if_log_rotated<F: ?Sized>(&mut self, callback: &F)
        where
            F: Fn(String, String, String) -> (String,bool),
    {
        loop {
            match File::open(self.filename.clone()) {
                Ok(x) => {
                    let f = x;
                    let metadata = match f.metadata() {
                        Ok(m) => m,
                        Err(_) => {
                            sleep(Duration::new(1, 0));
                            continue;
                        }
                    };
                    if metadata.ino() != self.inode {
                        self.finish = true;
                        self.watch(callback);
                        self.finish = false;
                        println!("reloading log file");
                        self.reader = BufReader::new(f);
                        self.pos = 0;
                        self.inode = metadata.ino();
                    } else {
                        sleep(Duration::new(1, 0));
                    }
                    break;
                }
                Err(err) => {
                    if err.kind() == ErrorKind::NotFound {
                        sleep(Duration::new(1, 0));
                        continue;
                    }
                }
            };
        }
    }

    pub fn watch<F: ?Sized>(&mut self, callback: &F)
        where
            F: Fn(String, String, String) -> (String,bool),
    {
        loop {
            let mut line = String::new();
            let resp = self.reader.read_line(&mut line);
            match resp {
                Ok(len) => {
                    if len > 0 {
                        self.pos += len as u64;
                        self.reader.seek(SeekFrom::Start(self.pos)).unwrap();
                        let (data,flag) = callback(line.replace("\n", ""), self.local_ip_str.clone(), self.hostname_str.clone());
                        if flag {
                            self.tx.send(data.as_bytes().to_vec()).expect("SEND_TO_CHANNEL_MSG_ERROR");
                        }
                        line.clear();
                    } else {
                        if self.finish {
                            break;
                        } else {
                            self.reopen_if_log_rotated(callback);
                            self.reader.seek(SeekFrom::Start(self.pos)).unwrap();
                        }
                    }
                }
                Err(err) => {
                    println!("{}", err);
                }
            }
        }
    }
}