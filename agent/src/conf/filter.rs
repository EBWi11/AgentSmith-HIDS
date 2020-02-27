pub const EXE_WHITELIST: &'static [&'static str] = &["/usr/libexec/pk-command-not-found","/usr/bin/chronyc","/usr/bin/as","/usr/bin/kmod","/usr/bin/ld.bfd","/usr/bin/gcc","/usr/lib64/sa/sa1","/usr/bin/date","/usr/lib64/sa","/usr/bin/test","/usr/sbin/chronyd","/usr/sbin/rsyslogd","/usr/bin/clear"];
pub const CONNECT_DIP_WHITELIST_IPV4: &'static [&'static str] = &["10.0.0.0/8", "172.16.0.0/16", "192.168.1.0/24", "127.0.0.1/32"];
pub const CONNECT_DIP_WHITELIST_IPV6: &'static [&'static str] = &["::1/128"];

pub const CREATE_FILE_ALERT_PATH: &'static [&'static str] = &["/etc/","/usr/etc/","/usr/local/etc/","/usr/bin/","/usr/sbin/","/usr/local/bin/","/usr/local/sbin/","/usr/lib/","/usr/lib64/","/usr/local/lib/","/usr/local/lib64/","/sys/","/boot/","/var/lib/","/app/bin/","/app/sbin/","/root/bin/"];
pub const CREATE_FILE_ALERT_SUFFIX: &'static [&'static str] = &[".sh",".php",".jsp",".asp",".aspx",".bash",".zsh",".csh",".service",".ini",".conf",".ko",".so",".d",".a",".htaccess"];
pub const CREATE_FILE_ALERT_CONTAINS: &'static [&'static str] = &["backdoor"];