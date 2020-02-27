extern crate chrono;
extern crate daemonize;
extern crate kafka;
extern crate libc;
extern crate serde;
extern crate crypto;
extern crate lru_time_cache;
extern crate iprange;
extern crate ipnet;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use conf::*;
use daemonize::Daemonize;
use lib::heartbeat::HeartBeat;
use lib::kafka_output::KafkaOutput;
use libc::c_char;
use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::File;
use std::io::prelude::*;
use std::process;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time;
use crypto::md5::Md5;
use crypto::digest::Digest;
use lru_time_cache::LruCache;
use lib::logwatcher::LogWatcher;
use std::time::{SystemTime, UNIX_EPOCH};
use iprange::IpRange;
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnet::{Ipv4Net, Ipv6Net};

mod lib;
mod conf;

extern { fn init(); }

extern { fn shm_init(); }

extern { fn shm_close(); }

extern { fn shm_run_no_callback() -> *const c_char; }

fn get_output_kafka(threads: u32) -> KafkaOutput {
    KafkaOutput::new(threads, settings::SEND_KAFKA_FAST_TYPE)
}

fn get_heartbeat(msg: String) -> HeartBeat {
    HeartBeat::new(settings::HEARTBEAT_SERVER.to_string(), msg)
}

fn parser_secure_log(data: String, local_ip_str: String, hostname_str: String) -> (String, bool) {
    let msg_split: Vec<&str> = data.split("]:").collect();
    let mut _msg_str = String::new();
    if msg_split.len() >= 2 {
        let tmp = "\"";
        let mut login_alert = ["{\"data_type\":\"1001\"".to_string(), ",\"status\":\"".to_string(), ",\"type\":\"".to_string(), ",\"user_exsit\":\"".to_string(), ",\"user\":\"".to_string(), ",\"from_ip\":\"".to_string(), ",\"port\":\"".to_string(), ",\"processor\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
        let data_split: Vec<&str> = msg_split[1].clone().trim().split(" ").collect();
        if data_split[0] == "Accepted" || data_split[0] == "Failed" {
            login_alert[1].push_str(&data_split[0]);
            login_alert[1].push_str(tmp);

            login_alert[2].push_str(&data_split[1]);
            login_alert[2].push_str(tmp);

            if data_split[3] == "invalid" && data_split[4] == "user" {
                login_alert[3].push_str("false");
                login_alert[3].push_str(tmp);

                login_alert[4].push_str(&data_split[5]);
                login_alert[4].push_str(tmp);

                login_alert[5].push_str(&data_split[7]);
                login_alert[5].push_str(tmp);

                login_alert[6].push_str(&data_split[9]);
                login_alert[6].push_str(tmp);

                login_alert[7].push_str(&data_split[10]);
                login_alert[7].push_str(tmp);

            } else {
                login_alert[3].push_str("true");
                login_alert[3].push_str(tmp);

                login_alert[4].push_str(&data_split[3]);
                login_alert[4].push_str(tmp);

                login_alert[5].push_str(&data_split[5]);
                login_alert[5].push_str(tmp);

                login_alert[6].push_str(&data_split[7]);
                login_alert[6].push_str(tmp);

                login_alert[7].push_str(&data_split[8]);
                login_alert[7].push_str(tmp);
            }

            let start = SystemTime::now();
            let since_the_epoch = start.duration_since(UNIX_EPOCH)
                .expect("Time went backwards");

            let in_ms = since_the_epoch.as_secs() * 1000 +
                since_the_epoch.subsec_nanos() as u64 / 1_000_000;

            let time = format!("{}", in_ms);

            login_alert[8].push_str(&time);
            login_alert[8].push_str(tmp);

            _msg_str = login_alert.join("");
            return (_msg_str, true)
        }
    }
    return (_msg_str, false)
}

fn get_secure_log(tx: Sender<Vec<u8>>) {
    let kafka_test_data = "0".as_bytes();

    let local_ip = get_machine_ip().replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ").replace("\n", " ");
    let hostname = get_hostname().replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ").replace("\n", " ");
    let local_ip_str = format!(",\"local_ip\":\"{}\"", local_ip);
    let hostname_str = format!(",\"hostname\":\"{}\"", hostname);

    thread::sleep(time::Duration::from_secs(1));
    tx.send(kafka_test_data.to_vec()).expect("KAFKA_INIT_ERROR");

    let mut log_watcher = LogWatcher::register("/var/log/secure".to_string(), local_ip_str.clone(), hostname_str.clone(), tx).unwrap();
    log_watcher.watch(&parser_secure_log);
}

fn get_data_no_callback(tx: Sender<Vec<u8>>) {
    let tmp = "\"";
    let kafka_test_data = "0".as_bytes();
    let mut exe_white_list = HashSet::new();
    let agent_pid = process::id().to_string();
    let cache_time = ::std::time::Duration::from_secs(900);

    for i in filter::EXE_WHITELIST.iter() {
        exe_white_list.insert(i.to_string());
    }

    let local_ip = get_machine_ip().replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ").replace("\n", " ");
    let hostname = get_hostname().replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ").replace("\n", " ");
    let local_ip_str = format!(",\"local_ip\":\"{}\"", local_ip);
    let hostname_str = format!(",\"hostname\":\"{}\"", hostname);

    let ipv4_whitelist_range: IpRange<Ipv4Net> = filter::CONNECT_DIP_WHITELIST_IPV4.iter()
        .map(|s| s.parse().expect("CONNECT_DIP_WHITELIST_IPV4_ERROR"))
        .collect();

    let ipv6_whitelist_range: IpRange<Ipv6Net> = filter::CONNECT_DIP_WHITELIST_IPV6.iter()
        .map(|s| s.parse().expect("CONNECT_DIP_WHITELIST_IPV6_ERROR"))
        .collect();

    thread::sleep(time::Duration::from_secs(1));
    tx.send(kafka_test_data.to_vec()).expect("KAFKA_INIT_ERROR");

    unsafe { shm_init(); };

    let mut cache = LruCache::<String, String>::with_expiry_duration_and_capacity(cache_time, 128);

    loop {
        let msg = unsafe { CStr::from_ptr(shm_run_no_callback()) }.to_string_lossy().clone();
        if msg.len() > 16 {
            let mut tmp_sa_family = "4";
            let mut md5_str;
            let mut send_flag = 0;
            let mut i = 1;
            let mut msg_str = String::new();
            let msg_split: Vec<&str> = msg.split("\n").collect();
            let mut msg_type = msg_split[1];

            let mut execve_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"run_path\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"argv\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"stdin\":\"".to_string(), ",\"stdout\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"dip\":\"".to_string(), ",\"dport\":\"".to_string(), ",\"sip\":\"".to_string(), ",\"sport\":\"".to_string(), ",\"sa_family\":\"".to_string(), ",\"pid_tree\":\"".to_string(), ",\"tty_name\":\"".to_string(), ",\"socket_process_pid\":\"".to_string(),",\"socket_process_exe\":\"".to_string(), ",\"SSH_CONNECTION\":\"".to_string(), ",\"LD_PRELOAD\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), ",\"socket_process_exe_md5\":\"".to_string(), "}".to_string()];
            let mut load_module_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"lkm_file\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), ",\"load_file_md5\":\"".to_string(),  "}".to_string()];
            let mut connect_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"sa_family\":\"".to_string(), ",\"fd\":\"".to_string(), ",\"dport\":\"".to_string(), ",\"dip\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sip\":\"".to_string(), ",\"sport\":\"".to_string(), ",\"res\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), "}".to_string()];
            let mut ptrace_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"ptrace_request\":\"".to_string(), ",\"target_pid\":\"".to_string(), ",\"addr\":\"".to_string(), ",\"data\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), "}".to_string()];
            let mut dns_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"sa_family\":\"".to_string(), ",\"fd\":\"".to_string(), ",\"dport\":\"".to_string(), ",\"dip\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sip\":\"".to_string(), ",\"sport\":\"".to_string(), ",\"qr\":\"".to_string(), ",\"opcode\":\"".to_string(), ",\"rcode\":\"".to_string(), ",\"query\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), "}".to_string()];
            let mut create_file_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"file_path\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), ",\"create_file_md5\":\"".to_string(), "}".to_string()];
            let mut proc_file_hook_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"module_name\":\"".to_string(), ",\"hidden\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut module_hidden_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"module_name\":\"".to_string(), ",\"hidden\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut interrupt_hook_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"module_name\":\"".to_string(), ",\"hidden\":\"".to_string(), ",\"interrupt_number\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut syscall_hook_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"module_name\":\"".to_string(), ",\"hidden\":\"".to_string(), ",\"syscall_number\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut update_cred_hook_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"old_uid\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), "}".to_string()];
            let mut mprotect_hook_msg = ["{".to_string(), "\"uid\":\"".to_string(), ",\"data_type\":\"".to_string(), ",\"exe\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"start\":\"".to_string(), ",\"len\":\"".to_string(), ",\"prot\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sessionid\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), ",\"exe_md5\":\"".to_string(), "}".to_string()];

            for s in msg_split {
                match msg_type {
                    "42" => {
                        if i == 8 || i == 9 || i == 10 || i == 11 {
                            if s == agent_pid {
                                msg_type = "-1";
                                break;
                            }
                        } else if i == 7 {
                            if exe_white_list.contains(s) {
                                msg_type = "-1";
                                break;
                            }

                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            connect_msg[22].push_str(&md5_str);
                            connect_msg[22].push_str(tmp);
                        } else if i == 3 {
                            tmp_sa_family = s.clone();
                        } else if i == 6 {
                            if tmp_sa_family == "2" {
                                if ipv4_whitelist_range.contains(&s.parse::<Ipv4Addr>().unwrap()) {
                                    msg_type = "-1";
                                    break;
                                }
                            } else if tmp_sa_family == "10" {
                                if ipv6_whitelist_range.contains(&s.parse::<Ipv6Addr>().unwrap()) {
                                    msg_type = "-1";
                                    break;
                                }
                            }
                        }
                        connect_msg[i].push_str(s);
                        connect_msg[i].push_str(tmp);
                    }

                    "59" => {
                        match i {
                            4 => {
                                if exe_white_list.contains(s) {
                                    msg_type = "-1";
                                    break;
                                } else {
                                    if s != "-1" {
                                        if !cache.contains_key(s) {
                                            md5_str = get_md5(s.to_string());
                                            cache.insert(s.to_string(), md5_str.clone());
                                        } else {
                                            md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                        }
                                    } else {
                                        md5_str = "-1".to_string();
                                    }
                                    execve_msg[30].push_str(&md5_str);
                                    execve_msg[30].push_str(tmp);
                                    execve_msg[i].push_str(s);
                                }
                            }

                            5 => {
                                let argv_res = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ");
                                execve_msg[i].push_str(argv_res.as_str());
                            }

                            6..=9 => {
                                if s == agent_pid {
                                    msg_type = "-1";
                                    break;
                                } else {
                                    execve_msg[i].push_str(s);
                                }
                            }

                            23 => {
                                if s != "-1" && s != "-2"{
                                    if !cache.contains_key(s) {
                                        md5_str = get_md5(s.to_string());
                                        cache.insert(s.to_string(), md5_str.clone());
                                    } else {
                                        md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                    }
                                } else {
                                    md5_str = "-1".to_string();
                                }
                                execve_msg[31].push_str(&md5_str);
                                execve_msg[31].push_str(tmp);
                                execve_msg[i].push_str(s);
                            }

                            _ => {
                                execve_msg[i].push_str(s);
                            }
                        };
                        execve_msg[i].push_str(tmp);
                    }

                    "101" => {
                        match i {
                            6 => {
                                let argv_res = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ").replace("\n", " ");
                                ptrace_msg[i].push_str(argv_res.as_str());
                            }

                            7 => {
                                if exe_white_list.contains(s) {
                                    msg_type = "-1";
                                    break;
                                }

                                if s != "-1" {
                                    if !cache.contains_key(s) {
                                        md5_str = get_md5(s.to_string());
                                        cache.insert(s.to_string(), md5_str.clone());
                                    } else {
                                        md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                    }
                                } else {
                                    md5_str = "-1".to_string();
                                }
                                ptrace_msg[19].push_str(&md5_str);
                                ptrace_msg[19].push_str(tmp);
                                ptrace_msg[i].push_str(s);
                            }

                            _ => {
                                ptrace_msg[i].push_str(s);
                            }
                        };
                        ptrace_msg[i].push_str(tmp);
                    }

                    "601" => {
                        if i == 8 || i == 9 || i == 10 || i == 11 {
                            if s == agent_pid {
                                msg_type = "-1";
                                break;
                            }
                        } else if i == 7 {
                            if exe_white_list.contains(s) {
                                msg_type = "-1";
                                break;
                            }
                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            dns_msg[25].push_str(&md5_str);
                            dns_msg[25].push_str(tmp);
                        }
                        dns_msg[i].push_str(s);
                        dns_msg[i].push_str(tmp);
                    }

                    "602" => {
                        if i == 5 || i == 6 || i == 7 || i == 8 {
                            if s == agent_pid {
                                msg_type = "-1";
                                break;
                            }
                        } else if i == 3 {
                            if exe_white_list.contains(s) {
                                msg_type = "-1";
                                break;
                            }
                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            create_file_msg[16].push_str(&md5_str);
                            create_file_msg[16].push_str(tmp);
                        } else if i == 4 {
                            let mut filename = "";
                            let mut filter_check_flag = false;

                            for i in filter::CREATE_FILE_ALERT_PATH.iter() {
                                if s.starts_with(i) {
                                    filter_check_flag = true;
                                    break;
                                }
                            }

                            if !filter_check_flag {
                                let tmp_splits: Vec<&str> = s.split("\\").collect();
                                filename = tmp_splits[tmp_splits.len()-1];
                                for i in filter::CREATE_FILE_ALERT_SUFFIX.iter() {
                                    if filename.ends_with(i) {
                                        filter_check_flag = true;
                                        break;
                                    }
                                }
                            }

                            if !filter_check_flag {
                                for i in filter::CREATE_FILE_ALERT_CONTAINS.iter() {
                                    if filename.contains(i) {
                                        filter_check_flag = true;
                                        break;
                                    }
                                }
                            }

                            if !filter_check_flag {
                                msg_type = "-1";
                                break;
                            }

                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            create_file_msg[17].push_str(&md5_str);
                            create_file_msg[17].push_str(tmp);
                        }
                        create_file_msg[i].push_str(s);
                        create_file_msg[i].push_str(tmp);
                    }

                    "603" => {
                        if i == 3 {
                            if exe_white_list.contains(s) {
                                msg_type = "-1";
                                break;
                            }
                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            load_module_msg[16].push_str(&md5_str);
                            load_module_msg[16].push_str(tmp);
                        } else if i == 4 {
                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            load_module_msg[17].push_str(&md5_str);
                            load_module_msg[17].push_str(tmp);
                        }
                        load_module_msg[i].push_str(s);
                        load_module_msg[i].push_str(tmp);
                    }

                    "604" => {
                        if i == 3 {
                            if exe_white_list.contains(s) {
                                msg_type = "-1";
                                break;
                            }

                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            update_cred_hook_msg[16].push_str(&md5_str);
                            update_cred_hook_msg[16].push_str(tmp);
                        }
                        update_cred_hook_msg[i].push_str(s);
                        update_cred_hook_msg[i].push_str(tmp);
                    }

                    "10" => {
                        if i == 3 {
                            if exe_white_list.contains(s) {
                                msg_type = "-1";
                                break;
                            }

                            if s != "-1" {
                                if !cache.contains_key(s) {
                                    md5_str = get_md5(s.to_string());
                                    cache.insert(s.to_string(), md5_str.clone());
                                } else {
                                    md5_str = cache.get(&s.to_string()).unwrap().to_string();
                                }
                            } else {
                                md5_str = "-1".to_string();
                            }
                            mprotect_hook_msg[18].push_str(&md5_str);
                            mprotect_hook_msg[18].push_str(tmp);
                        }
                        mprotect_hook_msg[i].push_str(s);
                        mprotect_hook_msg[i].push_str(tmp);
                    }

                    "700" => {
                        proc_file_hook_msg[i].push_str(s);
                        proc_file_hook_msg[i].push_str(tmp);
                    }

                    "701" => {
                        syscall_hook_msg[i].push_str(s);
                        syscall_hook_msg[i].push_str(tmp);
                    }

                    "702" => {
                        module_hidden_msg[i].push_str(s);
                        module_hidden_msg[i].push_str(tmp);
                    }

                    "703" => {
                        interrupt_hook_msg[i].push_str(s);
                        interrupt_hook_msg[i].push_str(tmp);
                    }

                    _ => {}
                }
                i = i + 1;
            }

            match msg_type {
                "10" => {
                    send_flag = 1;
                    msg_str = mprotect_hook_msg.join("");
                }

                "42" => {
                    send_flag = 1;
                    msg_str = connect_msg.join("");
                }

                "59" => {
                    send_flag = 1;
                    msg_str = execve_msg.join("");
                }

                "101" => {
                    send_flag = 1;
                    msg_str = ptrace_msg.join("");
                }

                "601" => {
                    send_flag = 1;
                    msg_str = dns_msg.join("");
                }

                "602" => {
                    send_flag = 1;
                    msg_str = create_file_msg.join("");
                }

                "603" => {
                    send_flag = 1;
                    msg_str = load_module_msg.join("");
                }

                "604" => {
                    send_flag = 1;
                    msg_str = update_cred_hook_msg.join("");
                }

                "700" => {
                    send_flag = 1;
                    msg_str = proc_file_hook_msg.join("");
                }

                "701" => {
                    send_flag = 1;
                    msg_str = syscall_hook_msg.join("");
                }

                "702" => {
                    send_flag = 1;
                    msg_str = module_hidden_msg.join("");
                }

                "703" => {
                    send_flag = 1;
                    msg_str = interrupt_hook_msg.join("");
                }

                _ => {}
            }

            if send_flag == 1 {
                tx.send(msg_str.as_bytes().to_vec()).expect("SEND_TO_CHANNEL_MSG_ERROR");
            }
        }
    }
}

fn write_pid() {
    let mut file = File::create(settings::PID_FILE_PATH).unwrap();
    file.write_all(process::id().to_string().as_bytes()).unwrap();
}

fn get_hostname() -> String {
    let output = Command::new("hostname")
        .output()
        .expect("GET_MACHINE_IP_ERROR");
    String::from_utf8_lossy(&output.stdout).to_string().trim().to_string()
}

fn get_machine_ip() -> String {
    let output = Command::new("hostname")
        .arg("-i")
        .output()
        .expect("GET_MACHINE_IP_ERROR");
    String::from_utf8_lossy(&output.stdout).to_string().trim().to_string()
}

fn get_md5(path: String) -> String {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_err) => return "-1".to_string(),
    };
    let mut buffer = Vec::new();
    let mut hasher = Md5::new();
    match file.read_to_end(&mut buffer) {
        Ok(buffer) => buffer,
        Err(_err) => return "-1".to_string(),
    };
    hasher.input(&buffer);
    return hasher.result_str();
}

fn check_lkm() -> bool {
    let output = Command::new("lsmod")
        .output()
        .expect("CHECK_LKM_ERROR");
    let out_str = String::from_utf8_lossy(&output.stdout);
    out_str.contains("smith")
}

fn run(tx: Sender<Vec<u8>>) {
    if check_lkm() {
        println!("SMITH_START");
        let tx1 = tx.clone();
        thread::spawn(move || { get_secure_log(tx1); });
        let tx2 = tx.clone();
        get_data_no_callback(tx2);
    } else {
        println!("NEED_INSTALL_LKM");
        if settings::AUTO_INSTALL_LKM {
            install_lkm();
        } else {
            thread::sleep(time::Duration::from_secs(3));
        }
    }
}

fn get_kernel_version() -> String {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .expect("GET_KERNEL_VERSION_ERROR");
    String::from_utf8_lossy(&output.stdout).to_string().trim().to_string()
}

fn start_hreatbread(tx: Sender<Vec<u8>>) {
    loop {
        let tx = tx.clone();
        let mut hb_msg = get_machine_ip();
        hb_msg.push_str("|ok");
        let hb = get_heartbeat(hb_msg);
        let handle = thread::spawn(move || { hb.run(tx); });
        match handle.join() {
            Err(_) => {
                println!("HREATBREAD_ERROR");
                thread::sleep(time::Duration::from_secs(3));
            }
            Ok(_) => {}
        }
    }
}

fn install_lkm() {
    Command::new("curl").arg("-o").arg(settings::LKM_TMP_PATH).arg(format!("{}lkm/release/{}/smith.ko", settings::LKM_SERVER, get_kernel_version())).status().unwrap();
    Command::new("insmod").arg(settings::LKM_TMP_PATH).status().unwrap();
    Command::new("rm").arg("-rf").arg(settings::LKM_TMP_PATH).status().unwrap();
    thread::sleep(time::Duration::from_secs(1));
}

fn action_wapper() {
    loop {
        unsafe { init(); };
        let handle = thread::spawn(move || action());
        match handle.join() {
            Err(_) => {
                println!("MAIN_ERROR");
                thread::sleep(time::Duration::from_secs(3));
            }
            Ok(_) => {}
        }
        thread::sleep(time::Duration::from_secs(3));
        unsafe { shm_close(); };
    }
}

fn action() {
    write_pid();

    let (tx, rx) = channel();
    let arx = Arc::new(Mutex::new(rx));
    let output = get_output_kafka(settings::DEFAULT_KAFKA_THREADS);
    output.start(arx);

    if settings::HEARTBEAT {
        let tx = tx.clone();
        thread::spawn(move || start_hreatbread(tx));
    }

    run(tx);
    thread::sleep(time::Duration::from_secs(2));
}

fn main_daemon() {
    let stdout = File::create(settings::SMITH_LOG_FILE).unwrap();
    let stderr = File::open(settings::SMITH_LOG_FILE).unwrap();

    let daemonize = Daemonize::new()
        .pid_file(settings::PID_FILE_PATH)
        .chown_pid_file(true)
        .user("nobody")
        .group("daemon")
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(|| action_wapper());

    match daemonize.start() {
        Ok(_) => println!("SUCCESS_SMITH_DAEMONIZED"),
        Err(e) => println!("START_SMITH_DAEMON_ERROR: {}", e),
    }
}

fn main() {
    if settings::DAEMON {
        main_daemon();
    } else {
        action_wapper();
    }
}