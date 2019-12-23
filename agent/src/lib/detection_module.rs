extern crate pipers;

use chrono::prelude::*;
use std::collections::HashMap;
use std::process::Command;

pub struct Detective {}

#[derive(Serialize, Deserialize)]
pub struct FileSystemIntegrityCheck {
    data_type: String,
    detection_name: String,
    ip: String,
    hostname: String,
    time: String,
    file_list: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ListeningSockets {
    data_type: String,
    detection_name: String,
    ip: String,
    hostname: String,
    time: String,
    list: Vec<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
pub struct RPMList {
    data_type: String,
    detection_name: String,
    ip: String,
    hostname: String,
    time: String,
    rpm_list: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemUser {
    data_type: String,
    detection_name: String,
    ip: String,
    hostname: String,
    time: String,
    user_list: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CrontabList {
    data_type: String,
    detection_name: String,
    ip: String,
    hostname: String,
    time: String,
    crontab_list: Vec<String>,
}

fn get_timestamp() -> String {
    let dt = Local::now();
    dt.timestamp_millis().to_string()
}

fn get_hostname() -> String {
    let output = Command::new("hostname")
        .output()
        .expect("GET_HOSTNAME_ERROR");
    String::from_utf8_lossy(&output.stdout).to_string().trim().to_string()
}

fn get_machine_ip() -> String {
    let output = Command::new("hostname")
        .arg("-i")
        .output()
        .expect("GET_MACHINE_IP_ERROR");
    String::from_utf8_lossy(&output.stdout).to_string().trim().to_string()
}

pub fn check_listening_sockets() -> String {
    let mut index = 0;
    let mut socket_list = Vec::new();

    let output = Command::new("ss")
        .arg("-nptul")
        .output()
        .expect("DETECTION check_listening_sockets() ERROR");

    let tmp_res = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let res_split: Vec<&str> = tmp_res.split("\n").collect();
    for i in res_split {
        if index == 0 {
            index = index + 1;
            continue;
        } else {
            index = index + 1;
            let mut tmp_split = i.split_whitespace();
            let mut tmp_one_res = HashMap::new();

            tmp_one_res.insert("Netid".to_string(), tmp_split.next().unwrap().to_string());
            tmp_one_res.insert("State".to_string(), tmp_split.next().unwrap().to_string());
            tmp_one_res.insert("Recv-Q".to_string(), tmp_split.next().unwrap().to_string());
            tmp_one_res.insert("Send-Q".to_string(), tmp_split.next().unwrap().to_string());
            tmp_one_res.insert("Local_Address".to_string(), tmp_split.next().unwrap().to_string());
            tmp_one_res.insert("Peer_Address".to_string(), tmp_split.next().unwrap().to_string());
            tmp_one_res.insert("Process_info".to_string(), tmp_split.next().unwrap().to_string());

            socket_list.push(tmp_one_res);
        }
    }

    let res_ori = ListeningSockets {
        data_type: String::from("detection_module"),
        detection_name: String::from("ListeningSockets"),
        ip: get_machine_ip(),
        hostname: get_hostname(),
        list: socket_list,
        time: get_timestamp(),
    };

    let res = serde_json::to_string(&res_ori).unwrap();
    res
}

pub fn get_rpm_list() -> String {
    let output = Command::new("rpm")
        .arg("-qa")
        .output()
        .expect("DETECTION get_rpm_list() ERROR");

    let mut rpm_list = Vec::new();

    let tmp_res = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let tmp_res_split: Vec<&str> = tmp_res.split("\n").collect();

    for i in tmp_res_split {
        rpm_list.push(i.to_string());
    }

    let res_ori = RPMList {
        data_type: String::from("detection_module"),
        detection_name: String::from("RPMList"),
        ip: get_machine_ip(),
        hostname: get_hostname(),
        rpm_list: rpm_list,
        time: get_timestamp(),
    };

    let res = serde_json::to_string(&res_ori).unwrap();
    res
}

pub fn get_system_user() -> String {
    let output = Command::new("cat")
        .arg("/etc/passwd")
        .output()
        .expect("DETECTION get_rpm_list() ERROR");

    let mut user_list = Vec::new();

    let tmp_res = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let tmp_res_split: Vec<&str> = tmp_res.split("\n").collect();

    for i in tmp_res_split {
        user_list.push(i.to_string());
    }

    let res_ori = SystemUser {
        data_type: String::from("detection_module"),
        detection_name: String::from("SystemUser"),
        ip: get_machine_ip(),
        hostname: get_hostname(),
        time: get_timestamp(),
        user_list: user_list,
    };

    let res = serde_json::to_string(&res_ori).unwrap();
    res
}

pub fn get_crontab_list() -> String {
    let output = Command::new("cat")
        .arg("/etc/passwd")
        .output()
        .expect("DETECTION get_crontab_list() ERROR");

    let tmp_res = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let res_split: Vec<&str> = tmp_res.split("\n").collect();
    let mut cron_list = Vec::new();

    for i in &res_split {
        let tmp_user_split: Vec<&str> = i.split(":").collect();
        if tmp_user_split.len() > 2 {
            let user = tmp_user_split[0];

            let user_crontab_output = Command::new("crontab")
                .arg("-l")
                .arg("-u")
                .arg(user)
                .output()
                .expect("DETECTION get_crontab_list() ERROR");

            let user_contab_res = String::from_utf8_lossy(&user_crontab_output.stdout).to_string().trim().to_string();
            let tmp_res_split: Vec<&str> = user_contab_res.split("\n").collect();
            for i2 in tmp_res_split {
                if i2 != "" {
                    cron_list.push(format!("{}:{}", user, i2));
                }
            }
        }
    }

    let cron_list_len = cron_list.len();

    let res_ori = CrontabList {
        data_type: String::from("detection_module"),
        detection_name: String::from("CrontabList"),
        ip: get_machine_ip(),
        hostname: get_hostname(),
        time: get_timestamp(),
        crontab_list: cron_list,
    };

    let res = serde_json::to_string(&res_ori).unwrap();

    if cron_list_len == 0 {
        return String::new();
    } else {
        return res;
    }
}

impl Detective {
    pub fn start(cmd: String) -> Vec<String> {
        let cmd_list: Vec<&str> = cmd.split(";").collect();
        let mut res_list: Vec<String> = Vec::new();

        for i in cmd_list {
            let mut res = "".to_string();
            match i {
                "ListeningSockets" => {
                    res = check_listening_sockets();
                }

                "RPMList" => {
                    res = get_rpm_list();
                }

                "SystemUser" => {
                    res = get_system_user();
                }

                "CrontabList" => {
                    res = get_crontab_list();
                }

                _ => {},
            }

            if res != "" {
                res_list.push(res);
            }
        }
        res_list
    }
}