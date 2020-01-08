use conf::*;
use kafka::producer::{Compression, Producer, Record, RequiredAcks};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time;

pub struct KafkaOutput {
    threads: u32,
    fast_send: bool,
}

struct KafkaWorker<'a> {
    arx: Arc<Mutex<Receiver<Vec<u8>>>>,
    producer: Producer,
    queue: Vec<Record<'a, (), Vec<u8>>>,
}

impl<'a> KafkaWorker<'a> {
    fn new(arx: Arc<Mutex<Receiver<Vec<u8>>>>) -> KafkaWorker<'a> {
        let compression = match settings::COMPRESSION
            .to_lowercase()
            .as_ref()
            {
                "none" => Compression::NONE,
                "gzip" => Compression::GZIP,
                "snappy" => Compression::SNAPPY,
                _ => panic!("Unsupported compression method. Only support: 'none','gzip','snappy'"),
            };

        let producer = Producer::from_hosts(settings::BROKER.to_owned()
            .split(',')
            .map(|s| s.trim().to_owned())
            .collect())
            .with_required_acks(RequiredAcks::One)
            .with_compression(compression)
            .create()
            .expect("CREATE_KAFKA_PRODUCER_ERROR");

        let queue = Vec::with_capacity(settings::COALESCE);
        KafkaWorker {
            arx: arx,
            producer: producer,
            queue: queue,
        }
    }

    fn run_nocoalesce(&'a mut self) {
        loop {
            let bytes = match { self.arx.lock().unwrap().recv() } {
                Ok(line) => line,
                Err(_) => continue,
            };
            match self
                .producer
                .send(&Record::from_value(settings::TOPIC, bytes))
                {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("KAFKA_ERROR: [{}]", e);
                    }
                }
        }
    }

    fn run_coalesce(&'a mut self) {
        loop {
            let bytes = match { self.arx.lock().unwrap().recv() } {
                Ok(line) => line,
                Err(_) => {
                    thread::sleep(time::Duration::from_millis(100));
                    continue;
                },
            };
            let message = Record {
                key: (),
                partition: -1,
                topic: settings::TOPIC,
                value: bytes,
            };
            let queue = &mut self.queue;
            queue.push(message);
            if queue.len() >= settings::COALESCE {
                match self.producer.send_all(queue) {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("KAFKA_ERROR: [{}]", e);
                    }
                }
                queue.clear();
            }
        }
    }

    fn run(&'a mut self) {
        self.run_coalesce();
    }

    fn run_fast(&'a mut self) {
        self.run_nocoalesce();
    }
}

impl KafkaOutput {
    pub fn new(threads: u32, fast_send: bool) -> KafkaOutput {
        KafkaOutput {
            threads: threads,
            fast_send: fast_send,
        }
    }

    pub fn start(&self, arx: Arc<Mutex<Receiver<Vec<u8>>>>) {
        if self.fast_send {
            for _ in 0..self.threads {
                let arx = Arc::clone(&arx);
                thread::spawn(move || {
                    let mut worker = KafkaWorker::new(arx);
                    worker.run_fast();
                });
            }
        } else {
            for _ in 0..self.threads {
                let arx = Arc::clone(&arx);
                thread::spawn(move || {
                    let mut worker = KafkaWorker::new(arx);
                    worker.run();
                });
            }
        }
    }
}