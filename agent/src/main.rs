extern crate chrono;
extern crate crypto;
extern crate daemonize;
extern crate ipnet;
extern crate iprange;
extern crate kafka;
extern crate libc;
extern crate lru_time_cache;
extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use conf::*;
use crypto::digest::Digest;
use crypto::md5::Md5;
use daemonize::Daemonize;
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use lib::heartbeat::HeartBeat;
use lib::kafka_output::KafkaOutput;
use lib::logwatcher::LogWatcher;
use libc::c_char;
use lru_time_cache::LruCache;
use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::File;
use std::io::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process;
use std::process::Command;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use std::time::{SystemTime, UNIX_EPOCH};

mod conf;
mod lib;

extern "C" {
    fn init();
}

extern "C" {
    fn shm_init();
}

extern "C" {
    fn shm_close();
}

extern "C" {
    fn shm_run_no_callback() -> *const c_char;
}

fn get_output_kafka(threads: u32) -> KafkaOutput {
    KafkaOutput::new(threads, settings::SEND_KAFKA_FAST_TYPE)
}

fn get_heartbeat(msg: String) -> HeartBeat {
    HeartBeat::new(settings::HEARTBEAT_SERVER.to_string(), msg)
}

fn parser_secure_log(data: String, local_ip: String, hostname: String) -> (String, bool) {
    let msg_split: Vec<&str> = data.split("]:").collect();
    let mut _msg_str = String::new();

    #[derive(Serialize, Deserialize)]
    struct LoginAlterStruct<T, U> {
        data_type: T,
        status: T,
        x_type: T,
        //for Will: need to rename this variable
        user_exsit: T,
        user: T,
        from_ip: T,
        port: T,
        processor: T,
        time: U,
        local_ip: T,
        hostname: T,
    }
    ;

    impl<T, U> LoginAlterStruct<T, U> {
        fn update_status_and_type(&mut self, status: T, x_type: T) {
            self.status = status;
            self.x_type = x_type;
        }

        fn update_userexsit_to_processor(
            &mut self,
            user_exsit: T,
            user: T,
            from_ip: T,
            port: T,
            processor: T,
        ) {
            self.user_exsit = user_exsit;
            self.user = user;
            self.from_ip = from_ip;
            self.port = port;
            self.processor = processor;
        }
    }

    let mut login_alert = LoginAlterStruct {
        data_type: "1001",
        status: "",
        x_type: "",
        user_exsit: "",
        user: "",
        from_ip: "",
        port: "",
        processor: "",
        time: 0,
        local_ip: "",
        hostname: "",
    };

    if msg_split.len() >= 2 {
        let data_split: Vec<&str> = msg_split[1].clone().trim().split(" ").collect();
        if data_split[0] == "Accepted" || data_split[0] == "Failed" {
            login_alert.update_status_and_type(&data_split[0], &data_split[1]);

            if data_split[3] == "invalid" && data_split[4] == "user" {
                login_alert.update_userexsit_to_processor(
                    "false",
                    data_split[5],
                    data_split[7],
                    data_split[9],
                    data_split[10],
                );
            } else {
                login_alert.update_userexsit_to_processor(
                    "true",
                    data_split[3],
                    data_split[5],
                    data_split[7],
                    data_split[8],
                );
            }

            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");

            let in_ms = since_the_epoch.as_secs() * 1000
                + since_the_epoch.subsec_nanos() as u64 / 1_000_000;

            login_alert.local_ip = &local_ip[..];
            login_alert.hostname = &hostname[..];
            login_alert.time = in_ms;

            let _msg_str: String = serde_json::to_string(&login_alert).unwrap();
            return (_msg_str, true);
        }
    }
    return (_msg_str, false);
}

fn get_secure_log(tx: Sender<Vec<u8>>) {
    let kafka_test_data = "0".as_bytes();
    let local_ip = trim_escape_character(get_machine_ip());
    let hostname = trim_escape_character(get_hostname());

    thread::sleep(time::Duration::from_secs(1));
    tx.send(kafka_test_data.to_vec()).expect("KAFKA_INIT_ERROR");

    let mut log_watcher = LogWatcher::register(
        "/var/log/secure".to_string(),
        local_ip.clone(),
        hostname.clone(),
        tx,
    )
        .unwrap();
    log_watcher.watch(&parser_secure_log);
}

fn get_data_no_callback(tx: Sender<Vec<u8>>) {
    let kafka_test_data = "0".as_bytes();
    let mut exe_white_list = HashSet::new();
    let agent_pid = process::id().to_string();
    let cache_time = ::std::time::Duration::from_secs(900);

    for i in filter::EXE_WHITELIST.iter() {
        exe_white_list.insert(i.to_string());
    }

    let local_ip = trim_escape_character(get_machine_ip());
    let hostname = trim_escape_character(get_hostname());
    let local_ip_str = local_ip.as_str();
    let hostname_str = hostname.as_str();

    let ipv4_whitelist_range: IpRange<Ipv4Net> = filter::CONNECT_DIP_WHITELIST_IPV4
        .iter()
        .map(|s| s.parse().expect("CONNECT_DIP_WHITELIST_IPV4_ERROR"))
        .collect();

    let ipv6_whitelist_range: IpRange<Ipv6Net> = filter::CONNECT_DIP_WHITELIST_IPV6
        .iter()
        .map(|s| s.parse().expect("CONNECT_DIP_WHITELIST_IPV6_ERROR"))
        .collect();

    thread::sleep(time::Duration::from_secs(1));
    tx.send(kafka_test_data.to_vec()).expect("KAFKA_INIT_ERROR");

    unsafe {
        shm_init();
    };

    let mut cache = LruCache::<String, String>::with_expiry_duration_and_capacity(cache_time, 128);

    loop {
        let msg = unsafe { CStr::from_ptr(shm_run_no_callback()) }
            .to_string_lossy()
            .clone();

        if msg.len() > 16 {
            #[derive(Serialize, Deserialize)]
            struct ExecveMsgStruct<T> {
                uid: T,
                data_type: T,
                run_path: T,
                exe: T,
                argv: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                stdin_content: T,
                //For will, element renamed, json content changed accordingly
                stdout_content: T,
                //For will, element renamed, json content changed accordingly
                sessionid: T,
                dip: T,
                dport: T,
                sip: T,
                sport: T,
                sa_family: T,
                pid_tree: T,
                tty_name: T,
                socket_process_pid: T,
                socket_process_exe: T,
                ssh_connection: T,
                ld_preload: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
                socket_process_exe_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct LoadModuleMsgStruct<T> {
                uid: T,
                data_type: T,
                exe: T,
                lkm_file: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
                load_file_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct ConnectMsgStruct<T> {
                uid: T,
                data_type: T,
                sa_family: T,
                fd: T,
                dport: T,
                dip: T,
                exe: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                sip: T,
                sport: T,
                res: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct BindMsgStruct<T> {
                uid: T,
                data_type: T,
                sa_family: T,
                exe: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                sip: T,
                sport: T,
                res: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct PtraceMsgStruct<T> {
                uid: T,
                data_type: T,
                ptrace_request: T,
                target_pid: T,
                addr: T,
                data: T,
                exe: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct DnsMsgStruct<T> {
                uid: T,
                data_type: T,
                sa_family: T,
                fd: T,
                dport: T,
                dip: T,
                exe: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                sip: T,
                sport: T,
                qr: T,
                opcode: T,
                rcode: T,
                query: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip: T,
                hostname: T,
                exe_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct CreateFileMsgStruct<T> {
                uid: T,
                data_type: T,
                exe: T,
                file_path: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                nodename: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
                create_file_md5: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct ProcFileHookMsgStruct<T> {
                uid: T,
                data_type: T,
                module_name: T,
                hidden: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct ModuleHiddenMsgStruct<T> {
                uid: T,
                data_type: T,
                module_name: T,
                hidden: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct InterruptHookMsgStruct<T> {
                uid: T,
                data_type: T,
                module_name: T,
                hidden: T,
                interrupt_number: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct SyscallHookMsgStruct<T> {
                uid: T,
                data_type: T,
                module_name: T,
                hidden: T,
                syscall_number: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
            }
            ;

            #[derive(Serialize, Deserialize)]
            struct UpdateCredHookMsgStruct<T> {
                uid: T,
                data_type: T,
                exe: T,
                pid: T,
                ppid: T,
                pgid: T,
                tgid: T,
                comm: T,
                old_uid: T,
                nodename: T,
                sessionid: T,
                user: T,
                time: T,
                local_ip_str: T,
                hostname_str: T,
                exe_md5: T,
            }
            ;

            let md5_str;
            let mut send_flag = 0;
            let mut msg_str = String::new();
            let msg_split: Vec<&str> = msg.split("\n").collect();
            let msg_type = msg_split[1];
            let tmp_sa_family = msg_split[2];
            let mut white_list_attr: bool = false;

            match msg_type {
                "49" => {
                    if tmp_sa_family == "2" {
                        if ipv4_whitelist_range.contains(&msg_split[5].parse::<Ipv4Addr>().unwrap())
                        {
                            white_list_attr = true;
                        }
                    } else if tmp_sa_family == "10" {
                        if ipv6_whitelist_range.contains(&msg_split[5].parse::<Ipv6Addr>().unwrap())
                        {
                            white_list_attr = true;
                        }
                    };

                    if exe_white_list.contains(msg_split[6]) {
                        white_list_attr = true;
                    };

                    if msg_split[4] == agent_pid
                        || msg_split[5] == agent_pid
                        || msg_split[6] == agent_pid
                        || msg_split[7] == agent_pid
                    {
                        white_list_attr = true;
                    };

                    if white_list_attr == false {
                        let mut bind_msg = BindMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            sa_family: msg_split[2],
                            exe: msg_split[3],
                            pid: msg_split[4],
                            ppid: msg_split[5],
                            pgid: msg_split[6],
                            tgid: msg_split[7],
                            comm: msg_split[8],
                            nodename: msg_split[9],
                            sip: msg_split[10],
                            sport: msg_split[11],
                            res: msg_split[12],
                            sessionid: msg_split[13],
                            user: msg_split[14],
                            time: msg_split[15],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                        };

                        if bind_msg.exe != "-1" {
                            if !cache.contains_key(bind_msg.exe) {
                                md5_str = get_md5(bind_msg.exe.to_string());
                                cache.insert(bind_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str =
                                    cache.get(&bind_msg.exe.to_string()).unwrap().to_string();
                            }
                            bind_msg.exe_md5 = &md5_str.as_str();
                        };

                        send_flag = 1;
                        msg_str = serde_json::to_string(&bind_msg).unwrap();
                    };
                }
                "42" => {
                    if tmp_sa_family == "2" {
                        if ipv4_whitelist_range.contains(&msg_split[5].parse::<Ipv4Addr>().unwrap())
                        {
                            white_list_attr = true;
                        }
                    } else if tmp_sa_family == "10" {
                        if ipv6_whitelist_range.contains(&msg_split[5].parse::<Ipv6Addr>().unwrap())
                        {
                            white_list_attr = true;
                        }
                    };

                    if exe_white_list.contains(msg_split[6]) {
                        white_list_attr = true;
                    };

                    if msg_split[7] == agent_pid
                        || msg_split[8] == agent_pid
                        || msg_split[9] == agent_pid
                        || msg_split[10] == agent_pid
                    {
                        white_list_attr = true;
                    };

                    if white_list_attr == false {
                        let mut connect_msg = ConnectMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            sa_family: msg_split[2],
                            fd: msg_split[3],
                            dport: msg_split[4],
                            dip: msg_split[5],
                            exe: msg_split[6],
                            pid: msg_split[7],
                            ppid: msg_split[8],
                            pgid: msg_split[9],
                            tgid: msg_split[10],
                            comm: msg_split[11],
                            nodename: msg_split[12],
                            sip: msg_split[13],
                            sport: msg_split[14],
                            res: msg_split[15],
                            sessionid: msg_split[16],
                            user: msg_split[17],
                            time: msg_split[18],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                        };

                        if connect_msg.exe != "-1" {
                            if !cache.contains_key(connect_msg.exe) {
                                md5_str = get_md5(connect_msg.exe.to_string());
                                cache.insert(connect_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str =
                                    cache.get(&connect_msg.exe.to_string()).unwrap().to_string();
                            }
                            connect_msg.exe_md5 = &md5_str.as_str();
                        };

                        send_flag = 1;
                        msg_str = serde_json::to_string(&connect_msg).unwrap();
                    };
                }

                "59" => {
                    if exe_white_list.contains(msg_split[3]) {
                        white_list_attr = true;
                    };

                    if msg_split[5] == agent_pid
                        || msg_split[6] == agent_pid
                        || msg_split[7] == agent_pid
                        || msg_split[8] == agent_pid
                    {
                        white_list_attr = true;
                    };

                    if white_list_attr == false {
                        let mut execve_msg = ExecveMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            run_path: msg_split[2],
                            exe: msg_split[3],
                            argv: "",
                            pid: msg_split[5],
                            ppid: msg_split[6],
                            pgid: msg_split[7],
                            tgid: msg_split[8],
                            comm: msg_split[9],
                            nodename: msg_split[10],
                            stdin_content: msg_split[11],
                            stdout_content: msg_split[12],
                            sessionid: msg_split[13],
                            dip: msg_split[14],
                            dport: msg_split[15],
                            sip: msg_split[16],
                            sport: msg_split[17],
                            sa_family: msg_split[18],
                            pid_tree: msg_split[19],
                            tty_name: msg_split[20],
                            socket_process_pid: msg_split[21],
                            socket_process_exe: msg_split[22],
                            ssh_connection: msg_split[23],
                            ld_preload: msg_split[24],
                            user: msg_split[25],
                            time: msg_split[26],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                            socket_process_exe_md5: "",
                        };

                        if execve_msg.exe != "-1" {
                            if !cache.contains_key(execve_msg.exe) {
                                md5_str = get_md5(execve_msg.exe.to_string());
                                cache.insert(execve_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str =
                                    cache.get(&execve_msg.exe.to_string()).unwrap().to_string();
                            }
                        } else {
                            md5_str = String::from("-1");
                        }
                        execve_msg.exe_md5 = md5_str.as_str();

                        let argv_res = trim_escape_character(msg_split[4].to_string()).clone();
                        execve_msg.argv = argv_res.as_str();

                        let md5_tmp;
                        if execve_msg.socket_process_exe != "-1"
                            && execve_msg.socket_process_exe != "-2"
                        {
                            if !cache.contains_key(execve_msg.socket_process_exe) {
                                md5_tmp = get_md5(execve_msg.socket_process_exe.to_string());
                                cache.insert(
                                    execve_msg.socket_process_exe.to_string(),
                                    md5_tmp.clone(),
                                );
                            } else {
                                md5_tmp = cache
                                    .get(&execve_msg.socket_process_exe.to_string())
                                    .unwrap()
                                    .to_string();
                            }
                        } else {
                            md5_tmp = "-1".to_string();
                        }
                        execve_msg.socket_process_exe_md5 = md5_tmp.as_str();
                        send_flag = 1;
                        msg_str = serde_json::to_string(&execve_msg).unwrap();
                    };
                }

                "101" => {
                    if exe_white_list.contains(msg_split[6]) {
                        white_list_attr = true;
                    };

                    if white_list_attr == false {
                        let mut ptrace_msg = PtraceMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            ptrace_request: msg_split[2],
                            target_pid: msg_split[3],
                            addr: msg_split[4],
                            data: "",
                            exe: msg_split[6],
                            pid: msg_split[7],
                            ppid: msg_split[8],
                            pgid: msg_split[9],
                            tgid: msg_split[10],
                            comm: msg_split[11],
                            nodename: msg_split[12],
                            sessionid: msg_split[13],
                            user: msg_split[14],
                            time: msg_split[15],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                        };

                        let argv_res = trim_escape_character(msg_split[5].to_string()).clone();
                        ptrace_msg.data = argv_res.as_str();

                        if ptrace_msg.exe != "-1" {
                            if !cache.contains_key(ptrace_msg.exe) {
                                md5_str = get_md5(ptrace_msg.exe.to_string());
                                cache.insert(ptrace_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str =
                                    cache.get(&ptrace_msg.exe.to_string()).unwrap().to_string();
                            }
                        } else {
                            md5_str = "-1".to_string();
                        }

                        ptrace_msg.exe_md5 = md5_str.as_str();
                        send_flag = 1;

                        msg_str = serde_json::to_string(&ptrace_msg).unwrap();
                    };
                }

                "601" => {
                    if msg_split[7] == agent_pid
                        || msg_split[8] == agent_pid
                        || msg_split[9] == agent_pid
                        || msg_split[10] == agent_pid
                    {
                        white_list_attr = true;
                    }

                    if exe_white_list.contains(msg_split[6]) {
                        white_list_attr = true;
                    }

                    if white_list_attr == false {
                        let mut dns_msg = DnsMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            sa_family: msg_split[2],
                            fd: msg_split[3],
                            dport: msg_split[4],
                            dip: msg_split[5],
                            exe: msg_split[6],
                            pid: msg_split[7],
                            ppid: msg_split[8],
                            pgid: msg_split[9],
                            tgid: msg_split[10],
                            comm: msg_split[11],
                            nodename: msg_split[12],
                            sip: msg_split[13],
                            sport: msg_split[14],
                            qr: msg_split[15],
                            opcode: msg_split[16],
                            rcode: msg_split[17],
                            query: msg_split[18],
                            sessionid: msg_split[19],
                            user: msg_split[20],
                            time: msg_split[21],
                            local_ip: local_ip_str,
                            hostname: hostname_str,
                            exe_md5: "",
                        };

                        if msg_split[6] != "-1" {
                            if !cache.contains_key(msg_split[6]) {
                                md5_str = get_md5(msg_split[6].to_string());
                                cache.insert(msg_split[6].to_string(), md5_str.clone());
                            } else {
                                md5_str = cache.get(&msg_split[6].to_string()).unwrap().to_string();
                            }
                        } else {
                            md5_str = "-1".to_string();
                        };
                        dns_msg.exe_md5 = md5_str.as_str();
                        send_flag = 1;
                        msg_str = serde_json::to_string(&dns_msg).unwrap();
                    }
                }

                "602" => {
                    if msg_split[4] == agent_pid
                        || msg_split[5] == agent_pid
                        || msg_split[6] == agent_pid
                        || msg_split[7] == agent_pid
                    {
                        white_list_attr = true;
                    };

                    if exe_white_list.contains(msg_split[2]) {
                        white_list_attr = true;
                    }

                    if white_list_attr == false {
                        let mut create_file_msg = CreateFileMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            exe: msg_split[2],
                            file_path: msg_split[3],
                            pid: msg_split[4],
                            ppid: msg_split[5],
                            pgid: msg_split[6],
                            tgid: msg_split[7],
                            comm: msg_split[8],
                            nodename: msg_split[9],
                            sessionid: msg_split[10],
                            user: msg_split[11],
                            time: msg_split[12],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                            create_file_md5: "",
                        };

                        if create_file_msg.exe != "-1" {
                            if !cache.contains_key(create_file_msg.exe) {
                                md5_str = get_md5(create_file_msg.exe.to_string());
                                cache.insert(create_file_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str =
                                    cache.get(&create_file_msg.exe.to_string()).unwrap().to_string();
                            }
                        } else {
                            md5_str = "-1".to_string();
                        }
                        create_file_msg.exe_md5 = md5_str.as_str();

                        let mut filename = "";
                        let mut filter_check_flag = false;
                        for item in filter::CREATE_FILE_ALERT_PATH.iter() {
                            if create_file_msg.file_path.starts_with(item) {
                                filter_check_flag = true;
                                break;
                            }
                        }

                        if !filter_check_flag {
                            let tmp_splits: Vec<&str> =
                                create_file_msg.file_path.split("\\").collect();
                            filename = tmp_splits[tmp_splits.len() - 1];
                            for item in filter::CREATE_FILE_ALERT_SUFFIX.iter() {
                                if filename.ends_with(item) {
                                    filter_check_flag = true;
                                    break;
                                }
                            }
                        }

                        if !filter_check_flag {
                            for item in filter::CREATE_FILE_ALERT_CONTAINS.iter() {
                                if filename.contains(item) {
                                    filter_check_flag = true;
                                    break;
                                }
                            }
                        }

                        if !filter_check_flag {}

                        let md5_tmp;
                        if create_file_msg.file_path != "-1" {
                            if !cache.contains_key(create_file_msg.file_path) {
                                md5_tmp = get_md5(create_file_msg.file_path.to_string());
                                cache
                                    .insert(create_file_msg.file_path.to_string(), md5_tmp.clone());
                            } else {
                                md5_tmp = cache
                                    .get(&create_file_msg.file_path.to_string())
                                    .unwrap()
                                    .to_string();
                            }
                        } else {
                            md5_tmp = "-1".to_string();
                        }
                        create_file_msg.create_file_md5 = md5_tmp.as_str();
                        send_flag = 1;
                        msg_str = serde_json::to_string(&create_file_msg).unwrap();
                    };
                }

                "603" => {
                    if exe_white_list.contains(msg_split[2]) {
                        white_list_attr = true;
                    }

                    if white_list_attr == false {
                        let mut load_module_msg = LoadModuleMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            exe: msg_split[2],
                            lkm_file: msg_split[3],
                            pid: msg_split[4],
                            ppid: msg_split[5],
                            pgid: msg_split[6],
                            tgid: msg_split[7],
                            comm: msg_split[8],
                            nodename: msg_split[9],
                            sessionid: msg_split[10],
                            user: msg_split[11],
                            time: msg_split[12],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                            load_file_md5: "",
                        };

                        if load_module_msg.exe != "-1" {
                            if !cache.contains_key(load_module_msg.exe) {
                                md5_str = get_md5(load_module_msg.exe.to_string());
                                cache.insert(load_module_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str = cache
                                    .get(&load_module_msg.exe.to_string())
                                    .unwrap()
                                    .to_string();
                            }
                        } else {
                            md5_str = "-1".to_string();
                        }
                        load_module_msg.exe_md5 = md5_str.as_str();

                        let md5_tmp;
                        if load_module_msg.lkm_file != "-1" {
                            if !cache.contains_key(load_module_msg.lkm_file) {
                                md5_tmp = get_md5(load_module_msg.lkm_file.to_string());
                                cache.insert(load_module_msg.lkm_file.to_string(), md5_tmp.clone());
                            } else {
                                md5_tmp = cache
                                    .get(&load_module_msg.lkm_file.to_string())
                                    .unwrap()
                                    .to_string();
                            }
                        } else {
                            md5_tmp = "-1".to_string();
                        }

                        load_module_msg.load_file_md5 = md5_tmp.as_str();
                        send_flag = 1;

                        msg_str = serde_json::to_string(&load_module_msg).unwrap();
                    }
                }

                "604" => {
                    if exe_white_list.contains(msg_split[2]) {
                        white_list_attr = true;
                    }

                    if white_list_attr == false {
                        let mut update_cred_hook_msg = UpdateCredHookMsgStruct {
                            uid: msg_split[0],
                            data_type: msg_split[1],
                            exe: msg_split[2],
                            pid: msg_split[3],
                            ppid: msg_split[4],
                            pgid: msg_split[5],
                            tgid: msg_split[6],
                            comm: msg_split[7],
                            old_uid: msg_split[8],
                            nodename: msg_split[9],
                            sessionid: msg_split[10],
                            user: msg_split[11],
                            time: msg_split[12],
                            local_ip_str: local_ip_str,
                            hostname_str: hostname_str,
                            exe_md5: "",
                        };

                        if update_cred_hook_msg.exe != "-1" {
                            if !cache.contains_key(update_cred_hook_msg.exe) {
                                md5_str = get_md5(update_cred_hook_msg.exe.to_string());
                                cache.insert(update_cred_hook_msg.exe.to_string(), md5_str.clone());
                            } else {
                                md5_str = cache
                                    .get(&update_cred_hook_msg.exe.to_string())
                                    .unwrap()
                                    .to_string();
                            }
                        } else {
                            md5_str = "-1".to_string();
                        }
                        update_cred_hook_msg.exe_md5 = md5_str.as_str();
                        send_flag = 1;
                        msg_str = serde_json::to_string(&update_cred_hook_msg).unwrap();
                    }
                }

                "700" => {
                    let proc_file_hook_msg = ProcFileHookMsgStruct {
                        uid: msg_split[0],
                        data_type: msg_split[1],
                        module_name: msg_split[2],
                        hidden: msg_split[3],
                        time: msg_split[4],
                        local_ip_str: local_ip_str,
                        hostname_str: hostname_str,
                    };
                    send_flag = 1;
                    msg_str = serde_json::to_string(&proc_file_hook_msg).unwrap();
                }

                "701" => {
                    let syscall_hook_msg = SyscallHookMsgStruct {
                        uid: msg_split[0],
                        data_type: msg_split[1],
                        module_name: msg_split[2],
                        hidden: msg_split[3],
                        syscall_number: msg_split[4],
                        time: msg_split[5],
                        local_ip_str: local_ip_str,
                        hostname_str: hostname_str,
                    };

                    send_flag = 1;
                    msg_str = serde_json::to_string(&syscall_hook_msg).unwrap();
                }

                "702" => {
                    let module_hidden_msg = ModuleHiddenMsgStruct {
                        uid: msg_split[0],
                        data_type: msg_split[1],
                        module_name: msg_split[2],
                        hidden: msg_split[3],
                        time: msg_split[4],
                        local_ip_str: local_ip_str,
                        hostname_str: hostname_str,
                    };
                    send_flag = 1;
                    msg_str = serde_json::to_string(&module_hidden_msg).unwrap();
                }

                "703" => {
                    let interrupt_hook_msg = InterruptHookMsgStruct {
                        uid: msg_split[0],
                        data_type: msg_split[1],
                        module_name: msg_split[2],
                        hidden: msg_split[3],
                        interrupt_number: msg_split[4],
                        time: msg_split[5],
                        local_ip_str: local_ip_str,
                        hostname_str: hostname_str,
                    };
                    send_flag = 1;
                    msg_str = serde_json::to_string(&interrupt_hook_msg).unwrap();
                }

                _ => {}
            }

            if send_flag == 1 {
                tx.send(msg_str.as_bytes().to_vec())
                    .expect("SEND_TO_CHANNEL_MSG_ERROR");
            };
        };
    };
}

fn write_pid() {
    let mut file = File::create(settings::PID_FILE_PATH).unwrap();
    file.write_all(process::id().to_string().as_bytes())
        .unwrap();
}

fn get_hostname() -> String {
    let output = Command::new("hostname")
        .output()
        .expect("GET_MACHINE_IP_ERROR");
    String::from_utf8_lossy(&output.stdout)
        .to_string()
        .trim()
        .to_string()
}

fn get_machine_ip() -> String {
    let output = Command::new("hostname")
        .arg("-i")
        .output()
        .expect("GET_MACHINE_IP_ERROR");
    String::from_utf8_lossy(&output.stdout)
        .to_string()
        .trim()
        .to_string()
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
    let output = Command::new("lsmod").output().expect("CHECK_LKM_ERROR");
    let out_str = String::from_utf8_lossy(&output.stdout);
    out_str.contains("smith")
}

fn run(tx: Sender<Vec<u8>>) {
    if check_lkm() {
        println!("SMITH_START");
        let tx1 = tx.clone();
        thread::spawn(move || {
            get_secure_log(tx1);
        });
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
    String::from_utf8_lossy(&output.stdout)
        .to_string()
        .trim()
        .to_string()
}

fn start_hreatbread(tx: Sender<Vec<u8>>) {
    loop {
        let tx = tx.clone();
        let mut hb_msg = get_machine_ip();
        hb_msg.push_str("|ok");
        let hb = get_heartbeat(hb_msg);
        let handle = thread::spawn(move || {
            hb.run(tx);
        });
        match handle.join() {
            Err(e) => {
                println!("HREATBREAD_ERROR: {:?}", e);
                thread::sleep(time::Duration::from_secs(3));
            }
            Ok(_) => {}
        }
    }
}

fn install_lkm() {
    Command::new("curl")
        .arg("-o")
        .arg(settings::LKM_TMP_PATH)
        .arg(format!(
            "{}lkm/release/{}/smith.ko",
            settings::LKM_SERVER,
            get_kernel_version()
        ))
        .status()
        .unwrap();
    Command::new("insmod")
        .arg(settings::LKM_TMP_PATH)
        .status()
        .unwrap();
    Command::new("rm")
        .arg("-rf")
        .arg(settings::LKM_TMP_PATH)
        .status()
        .unwrap();
    thread::sleep(time::Duration::from_secs(1));
}

fn action_wapper() {
    loop {
        unsafe {
            init();
        };
        let handle = thread::spawn(move || action());
        match handle.join() {
            Err(e) => {
                println!("MAIN_ERROR: {:?}", e);
                thread::sleep(time::Duration::from_secs(3));
            }
            Ok(_) => {}
        }
        thread::sleep(time::Duration::from_secs(3));
        unsafe {
            shm_close();
        };
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

fn trim_escape_character(mut ori_string: String) -> String {
    let escape_character = [
        ("\\", "\\\\"),
        ("\'", "\\\'"),
        ("\t", " "),
        ("\"", "\\\""),
        ("\n", " "),
    ];
    for items in &escape_character {
        ori_string = ori_string.replace(items.0, items.1);
    }
    return ori_string;
}

fn main() {
    if settings::DAEMON {
        main_daemon();
    } else {
        action_wapper();
    }
}
