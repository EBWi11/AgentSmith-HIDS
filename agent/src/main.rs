extern crate chrono;
extern crate daemonize;
extern crate kafka;
extern crate libc;
extern crate serde;
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

fn get_data_no_callback(tx: Sender<Vec<u8>>) {
    let tmp = "\"";
    let kafka_test_data = "0".as_bytes();
    let mut connect_white_list = HashSet::new();
    let mut execve_white_list = HashSet::new();
    let mut accept_white_list = HashSet::new();
    let agent_pid = process::id().to_string();

    for i in whitelist::CONNET.iter() {
        connect_white_list.insert(i.to_string());
    }

    for i in whitelist::EXECVE.iter() {
        execve_white_list.insert(i.to_string());
    }
    
    for i in whitelist::ACCEPT.iter() {
        accept_white_list.insert(i.to_string());
    }

    let local_ip = get_machine_ip();
    let hostname = get_hostname();
    let local_ip_str = format!(",\"local_ip\":\"{}\"", local_ip);
    let hostname_str = format!(",\"hostname\":\"{}\"", hostname);

    thread::sleep(time::Duration::from_secs(1));
    tx.send(kafka_test_data.to_vec()).expect("KAFKA_INIT_ERROR");

    unsafe { shm_init(); };

    loop {
        let msg = unsafe { CStr::from_ptr(shm_run_no_callback()) }.to_string_lossy().clone();
        if msg.len() > 16 {
            let mut send_flag = 0;
            let mut i = 2;
            let mut msg_str = String::new();
            let msg_split: Vec<&str> = msg.split("\n").collect();
            let mut msg_syscall_type = msg_split[1];
            let mut argv_res = String::with_capacity(4096);

            let mut syscall_execve_msg = ["{".to_string(), "\"data_type\":\"syscall\",".to_string(), "\"uid\":\"".to_string(), ",\"syscall\":\"".to_string(), ",\"run_path\":\"".to_string(), ",\"elf\":\"".to_string(), ",\"argv\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"stdin\":\"".to_string(), ",\"stdout\":\"".to_string(), ",\"pid_rootkit_check\":\"".to_string(),",\"ppid_rootkit_check\":\"".to_string(),",\"file_rootkit_check\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut syscall_init_msg = ["{".to_string(), "\"data_type\":\"syscall\",".to_string(), "\"uid\":\"".to_string(), ",\"syscall\":\"".to_string(), ",\"cwd\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), ",\"CR0_check\":".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut syscall_finit_msg = ["{".to_string(), "\"data_type\":\"syscall\",".to_string(), "\"uid\":\"".to_string(), ",\"syscall\":\"".to_string(), ",\"cwd\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), ",\"CR0_check\":".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut syscall_connect_msg = ["{".to_string(), "\"data_type\":\"syscall\",".to_string(), "\"uid\":\"".to_string(), ",\"syscall\":\"".to_string(), ",\"sa_family\":\"".to_string(), ",\"fd\":\"".to_string(), ",\"dport\":\"".to_string(), ",\"dip\":\"".to_string(), ",\"elf\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"sip\":\"".to_string(), ",\"sport\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];
            let mut syscall_accept_msg = ["{".to_string(), "\"data_type\":\"syscall\",".to_string(), "\"uid\":\"".to_string(), ",\"syscall\":\"".to_string(), ",\"sa_family\":\"".to_string(), ",\"fd\":\"".to_string(), ",\"sport\":\"".to_string(), ",\"sip\":\"".to_string(), ",\"elf\":\"".to_string(), ",\"pid\":\"".to_string(), ",\"ppid\":\"".to_string(), ",\"pgid\":\"".to_string(), ",\"tgid\":\"".to_string(), ",\"comm\":\"".to_string(), ",\"nodename\":\"".to_string(), ",\"dip\":\"".to_string(), ",\"dport\":\"".to_string(), ",\"user\":\"".to_string(), ",\"time\":\"".to_string(), local_ip_str.to_string(), hostname_str.to_string(), "}".to_string()];

            for mut s in msg_split {
                if msg_syscall_type == "59" {
                    if i == 5 {
                        if execve_white_list.contains(s) {
                            msg_syscall_type = "-1";
                            break;
                        }
                    }
                    if i == 7 || i == 8 || i == 9 || i == 10 {
                        if s == agent_pid {
                            msg_syscall_type = "-1";
                            break;
                        }
                    }

                    if i == 6 {
                        argv_res = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", " ");
                        syscall_execve_msg[i].push_str(argv_res.as_str());
                        syscall_execve_msg[i].push_str(tmp);
                    } else {
                        syscall_execve_msg[i].push_str(s);
                        syscall_execve_msg[i].push_str(tmp);
                    }
                } else if msg_syscall_type == "175" {
                    if i == 4 {
                        if check_cr0(s.to_string()) {
                            syscall_init_msg[13].push_str("true");
                        } else {
                            syscall_init_msg[13].push_str("false");
                        }
                    }
                    syscall_init_msg[i].push_str(s);
                    syscall_init_msg[i].push_str(tmp);
                } else if msg_syscall_type == "313" {
                    if i == 4 {
                        if check_cr0(s.to_string()) {
                            syscall_finit_msg[13].push_str("true");
                        } else {
                            syscall_finit_msg[13].push_str("false");
                        }
                    }
                    syscall_finit_msg[i].push_str(s);
                    syscall_finit_msg[i].push_str(tmp);
                } else if msg_syscall_type == "42" {
                    if i == 9 || i == 10 || i == 11 || i == 12 {
                        if s == agent_pid {
                            msg_syscall_type = "-1";
                            break;
                        }
                    }
                    if i == 8 {
                        if connect_white_list.contains(s) {
                            msg_syscall_type = "-1";
                            break;
                        }
                    }
                    syscall_connect_msg[i].push_str(s);
                    syscall_connect_msg[i].push_str(tmp);
                } else if msg_syscall_type == "43" {
                    if i == 9 || i == 10 || i == 11 || i == 12 {
                        if s == agent_pid {
                            msg_syscall_type = "-1";
                            break;
                        }
                    }
                    if i == 8 {
                        if accept_white_list.contains(s) {
                            msg_syscall_type = "-1";
                            break;
                        }
                    }
                    syscall_accept_msg[i].push_str(s);
                    syscall_accept_msg[i].push_str(tmp);
                }
                i = i + 1;
            }

            if msg_syscall_type == "59" {
                send_flag = 1;
                msg_str = syscall_execve_msg.join("");
            } else if msg_syscall_type == "175" {
                send_flag = 1;
                msg_str = syscall_init_msg.join("");
            } else if msg_syscall_type == "313" {
                send_flag = 1;
                msg_str = syscall_finit_msg.join("");
            } else if msg_syscall_type == "42" {
                send_flag = 1;
                msg_str = syscall_connect_msg.join("");
            } else if msg_syscall_type == "43" {
                send_flag = 1;
                msg_str = syscall_accept_msg.join("");
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

fn check_cr0(mut path: String) -> bool {
    false
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

fn check_lkm() -> bool {
    let output = Command::new("lsmod")
        .output()
        .expect("CHECK_LKM_ERROR");
    let out_str = String::from_utf8_lossy(&output.stdout);
    out_str.contains("syshook")
}

fn run(tx: Sender<Vec<u8>>) {
    if check_lkm() {
        println!("SMITH_START");
        get_data_no_callback(tx);
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
    Command::new("curl").arg("-o").arg(settings::LKM_TMP_PATH).arg(format!("{}lkm/release/{}/syshook.ko", settings::LKM_SERVER, get_kernel_version())).status().unwrap();
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