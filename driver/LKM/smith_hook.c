/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2019
* File:		smith_hook.c
* Description:	get execve,connect,bind,ptrace,load_module,dns_query,create_file,cred_change,proc_file_hook,syscall_hook,lkm_hidden,interrupts_hook info

* AgentSmith-HIDS is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* AgentSmith-HIDS is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* see <https://www.gnu.org/licenses/>.
*******************************************************************/
#include "share_mem.h"
#include "anti_rootkit.h"
#include "smith_hook.h"
#include "filter.h"
#include "struct_wrap.h"

#define EXIT_PROTECT 0
#define ROOTKIT_CHECK 1

#define CONNECT_HOOK 1
#define BIND_HOOK 1
#define EXECVE_HOOK 1
#define CREATE_FILE_HOOK 1
#define PTRACE_HOOK 1
#define DNS_HOOK 1
#define LOAD_MODULE_HOOK 1
#define UPDATE_CRED_HOOK 1

#define MAXACTIVE 32 * NR_CPUS

#define PID_TREE_LIMIT 8
#define EXECVE_GET_SOCK_FD_LIMIT 8
#define EXECVE_GET_SOCK_PPID_LIMIT 8

int share_mem_flag = -1;
int checkCPUendianRes = 0;

char bind_kprobe_state = 0x0;
char execve_kprobe_state = 0x0;
char compat_execve_kprobe_state = 0x0;
char create_file_kprobe_state = 0x0;
char ptrace_kprobe_state = 0x0;
char udp_recvmsg_kprobe_state = 0x0;
char udpv6_recvmsg_kprobe_state = 0x0;
char load_module_kprobe_state = 0x0;
char update_cred_kprobe_state = 0x0;
char ip4_datagram_connect_kprobe_state = 0x0;
char ip6_datagram_connect_kprobe_state = 0x0;
char tcp_v4_connect_kprobe_state = 0x0;
char tcp_v6_connect_kprobe_state = 0x0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
char execveat_kretprobe_state = 0x0;
char compat_execveat_kretprobe_state = 0x0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
struct user_arg_ptr
{
#ifdef CONFIG_COMPAT
        bool is_compat;
#endif
        union {
            const char __user *const __user *native;
#ifdef CONFIG_COMPAT
            const compat_uptr_t __user *compat;
#endif
            } ptr;
};

const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat))
    {
        compat_uptr_t compat;

        if (get_user(compat, argv.ptr.compat + nr))
            return ERR_PTR(-EFAULT);

        return compat_ptr(compat);
    }
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

int count(struct user_arg_ptr argv, int max)
{
    int i = 0;
    if (argv.ptr.native != NULL) {
        for (;;) {
            const char __user *p = get_user_arg_ptr(argv, i);
            if (!p)
                break;
            if (IS_ERR(p))
                return -EFAULT;
            if (i >= max)
                return -E2BIG;
            ++i;
            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}
#else

int count(char **argv, int max) {
    int i = 0;

    if (argv != NULL) {
        for (;;) {
            char *p;

            if (get_user(p, argv))
                return -EFAULT;
            if (!p)
                break;
            argv++;
            if (i++ >= max)
                return -E2BIG;

            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}

#endif

char *_dentry_path_raw(void) {
    char *cwd;
    char *pname_buf = NULL;
    struct path pwd;
    pwd = current->fs->pwd;
    path_get(&pwd);
    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf))
        return "-1";
    cwd = d_path(&pwd, pname_buf, PATH_MAX);
    kfree(pname_buf);
    return cwd;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
char *getfullpath(struct inode *inod,char *buffer,int len)
{
    struct hlist_node* plist = NULL;
    struct dentry* tmp = NULL;
    struct dentry* dent = NULL;
    char* name = NULL;
    struct inode* pinode = inod;

    buffer[len - 1] = '\0';
    if(unlikely(!pinode))
        return NULL;

    hlist_for_each(plist, &pinode->i_dentry) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 16, 7)
        tmp = hlist_entry(plist, struct dentry, d_u.d_alias);
#else
        tmp = hlist_entry(plist, struct dentry, d_alias);
#endif
        if(tmp->d_inode == pinode) {
            dent = tmp;
            break;
        }
    }

    if(unlikely(!dent))
        return NULL;

    name = dentry_path_raw(dent, buffer, len);
    return name;
}
#else

int prepend(char **buffer, int *buflen, const char *str, int namelen) {
    *buflen -= namelen;
    if (*buflen < 0)
        return -ENAMETOOLONG;
    *buffer -= namelen;
    memcpy(*buffer, str, namelen);
    return 0;
}

int prepend_name(char **buffer, int *buflen, struct qstr *name) {
    return prepend(buffer, buflen, name->name, name->len);
}

char *__dentry_path(struct dentry *dentry, char *buf, int buflen) {
    char *end = buf + buflen;
    char *retval;

    prepend(&end, &buflen, "\0", 1);
    if (buflen < 1)
        goto Elong;
    retval = end - 1;
    *retval = '/';

    while (!IS_ROOT(dentry)) {
        struct dentry *parent = dentry->d_parent;
        int error;

        prefetch(parent);
        spin_lock(&dentry->d_lock);
        error = prepend_name(&end, &buflen, &dentry->d_name);
        spin_unlock(&dentry->d_lock);
        if (error != 0 || prepend(&end, &buflen, "/", 1) != 0)
            goto Elong;

        retval = end;
        dentry = parent;
    }
    return retval;
    Elong:
    return ERR_PTR(-ENAMETOOLONG);
}

char *getfullpath(struct inode *inod, char *buffer, int len) {
    struct list_head *plist = NULL;
    struct dentry *tmp = NULL;
    struct dentry *dent = NULL;
    char *name = NULL;
    struct inode *pinode = inod;

    buffer[PATH_MAX - 1] = '\0';
    if (unlikely(!pinode))
        return NULL;

    spin_lock(&pinode->i_lock);
    list_for_each(plist, &pinode->i_dentry)
    {
        tmp = list_entry(plist,
        struct dentry, d_alias);
        if (tmp->d_inode == pinode) {
            dent = tmp;
            break;
        }
    }
    spin_unlock(&pinode->i_lock);

    if (unlikely(!dent))
        return NULL;

    spin_lock(&inod->i_lock);
    name = __dentry_path(dent, buffer, len);
    spin_unlock(&inod->i_lock);

    return name;
}

#endif

char *get_exe_file(struct task_struct *task, char *buffer, int size) {
    char *exe_file_str = "-1";

    if (unlikely(!buffer)) {
        exe_file_str = "-1";
        return exe_file_str;
    }

    if (likely(task->mm)) {
        if (likely(task->mm->exe_file)) {
            char pathname[PATH_MAX];
            memset(pathname, 0, PATH_MAX);
            exe_file_str = d_path(&task->mm->exe_file->f_path, buffer, size);
        }
    }

    if (unlikely(IS_ERR(exe_file_str))) {
        exe_file_str = "-1";
    }

    return exe_file_str;
}

char *str_replace(char *orig, char *rep, char *with) {
    char *result, *ins, *tmp;
    int len_rep, len_with, len_front, count;

    if (!orig || !rep)
        return NULL;

    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL;

    if (!with)
        with = "";

    len_with = strlen(with);

    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count)
        ins = tmp + len_rep;

    tmp = result = kzalloc(strlen(orig) + (len_with - len_rep) * count + 1, GFP_ATOMIC);

    if (unlikely(!result))
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }

    strcpy(tmp, orig);
    return result;
}

char *get_pid_tree(void) {
    int data_len;
    int limit_index = 0;
    int comm_free = 0;
    char *tmp_data = NULL;
    char *res = NULL;
    char *comm = NULL;
    char pid[sizeof(size_t)];
    struct task_struct *task;

    task = current;

    if (strlen(task->comm) > 0) {
        comm = str_replace(current->comm, "\n", " ");
        if (likely(comm))
            comm_free = 1;
        else
            comm = "";
    } else
        comm = "";

    snprintf(pid, sizeof(size_t), "%d", task->pid);
    tmp_data = kzalloc(4096, GFP_ATOMIC);

    if (unlikely(!tmp_data)) {
        if (comm_free == 1)
            kfree(comm);
        return NULL;
    }

    strcat(tmp_data, pid);
    strcat(tmp_data, "(");
    strcat(tmp_data, comm);
    strcat(tmp_data, ")");

    if (likely(comm_free == 1))
        kfree(comm);

    while (task->pid != 1) {
        comm_free = 0;
        limit_index = limit_index + 1;
        if (limit_index > PID_TREE_LIMIT)
            break;

        task = task->parent;
        data_len = strlen(task->comm) + sizeof(size_t) + 8;

        if (data_len > sizeof(size_t) + 8) {
            comm = str_replace(task->comm, "\n", " ");
            if (likely(comm))
                comm_free = 1;
            else
                comm = "";
        } else
            comm = "";

        res = kzalloc(data_len + strlen(tmp_data), GFP_ATOMIC);

        if (unlikely(!res)) {
            kfree(res);
            if (likely(comm_free == 1))
                kfree(comm);
            return NULL;
        }

        snprintf(pid, sizeof(size_t), "%d", task->pid);
        strcat(res, pid);
        strcat(res, "(");
        strcat(res, comm);
        strcat(res, ")->");
        strcat(res, tmp_data);
        strncpy(tmp_data, res, strlen(res));
        kfree(res);

        if (likely(comm_free == 1))
            kfree(comm);
    }

    return tmp_data;
}

struct bind_data {
    int fd;
    struct sockaddr *dirp;
};

struct connect_data {
    struct sock *sk;
    int sa_family;
    int type;
};

struct udp_recvmsg_data {
    char sport[16];
    char dport[16];
    char sip[64];
    char dip[64];
    int sa_family;
    int flag;
    void __user *iov_base;
    __kernel_size_t iov_len;
};

#if EXIT_PROTECT == 1
void exit_protect_action(void)
{
    __module_get(THIS_MODULE);
}
#endif

int checkCPUendian(void) {
    union {
        unsigned long int i;
        unsigned char s[4];
    } c;
    c.i = 0x12345678;
    return (0x12 == c.s[0]);
}

unsigned short int Ntohs(unsigned short int n) {
    return checkCPUendianRes ? n : BigLittleSwap16(n);
}

unsigned int get_sessionid(void) {
    unsigned int sessionid = 0;
#ifdef CONFIG_AUDITSYSCALL
    sessionid = current -> sessionid;
#endif
    return sessionid;
}

int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct bind_data *data;
    if (share_mem_flag != -1) {
        data = (struct bind_data *) ri->data;
        data->dirp = (struct sockaddr *) p_get_arg2(regs);
    }
    return 0;
}

int bind_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int flag = 0;
    int copy_res;
    int retval;
    int sa_family;
    int result_str_len;
    int comm_free = 0;
    unsigned int sessionid;
    char sip[64] = "-1";
    char sport[16] = "-1";
    char *abs_path = NULL;
    char *result_str;
    char *comm = NULL;
    char *buffer = NULL;
    struct sockaddr tmp_dirp;
    struct bind_data *data;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    if (share_mem_flag == -1)
        return 0;

    retval = regs_return_value(regs);
    data = (struct bind_data *) ri->data;

    if(IS_ERR_OR_NULL(data->dirp))
        goto out;

    copy_res = copy_from_user(&tmp_dirp, data->dirp, 16);

    if (unlikely(copy_res))
        goto out;

    switch (tmp_dirp.sa_family) {
        case AF_INET:
            sin = (struct sockaddr_in *) &tmp_dirp;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
            if (likely(tmp_dirp.sa_data)) {
                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(sin->sin_addr));
                snprintf(sport, 16, "%d", Ntohs(sin->sin_port));
                flag = 1;
            }
#else
            if (likely(tmp_dirp.sa_data)) {
                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(sin->sin_addr));
                snprintf(sport, 16, "%d", Ntohs(sin->sin_port));
                flag = 1;
            }
#endif
            sa_family = AF_INET;
            break;
#if IS_ENABLED(CONFIG_IPV6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) &tmp_dirp;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
                if (likely(tmp_dirp.sa_data)) {
                    snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sin6->sin6_addr));
                    snprintf(sport, 16, "%d", Ntohs(sin6->sin6_port));
                    flag = 1;
                }
#else
                if (likely(tmp_dirp.sa_data)) {
                    snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sin6->sin6_addr));
                    snprintf(sport, 16, "%d", Ntohs(sin6->sin6_port));
                    flag = 1;
                }
#endif
                sa_family = AF_INET6;
                break;
#endif
        default:
            break;
    }

    if (flag == 1) {
        sessionid = get_sessionid();
        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);

        if (unlikely(!buffer))
            abs_path = "-2";
        else
            abs_path = get_exe_file(current, buffer, PATH_MAX);

        if (strlen(current->comm) > 0) {
            comm = str_replace(current->comm, "\n", " ");
            if (likely(comm))
                comm_free = 1;
            else
                comm = "";
        } else
            comm = "";

        result_str_len = strlen(current->nsproxy->uts_ns->name.nodename) +
                         strlen(comm) + strlen(abs_path) + 172;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);
        if (likely(result_str)) {
            snprintf(result_str, result_str_len,
                     "%d\n%s\n%d\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%s\n%s\n%d\n%u",
                     get_current_uid(), BIND_TYPE, sa_family,
                     abs_path, current->pid, current->real_parent->pid,
                     pid_vnr(task_pgrp(current)), current->tgid,
                     comm, current->nsproxy->uts_ns->name.nodename,
                     sip, sport, retval, sessionid);
            send_msg_to_user(result_str, 1);
        }

        if (likely(strcmp(abs_path, "-2")))
            kfree(buffer);

        if (likely(comm_free == 1))
            kfree(comm);
    }

    return 0;

    out:
    return 0;
}

int connect_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int flag = 0;
    int retval;
    int comm_free = 0;
    int result_str_len;
    unsigned int sessionid;
    char dip[64] = "-1";
    char sip[64] = "-1";
    char dport[16] = "-1";
    char sport[16] = "-1";
    char *abs_path = NULL;
    char *result_str;
    char *comm = NULL;
    char *buffer = NULL;
    struct sock *sk;
    struct connect_data *data;
    struct inet_sock *inet;

    if (share_mem_flag == -1)
        return 0;

    retval = regs_return_value(regs);
    data = (struct connect_data *) ri->data;

    sk = data->sk;
    if(unlikely(IS_ERR_OR_NULL(sk)))
        return 0;

    inet = (struct inet_sock *) sk;

    switch (data->sa_family) {
        case AF_INET:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
            if (likely(inet->inet_daddr)) {
                snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_daddr));
                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_saddr));
                snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                flag = 1;
            }
#else
            if (likely(inet->daddr)) {
                snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->daddr));
                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->saddr));
                snprintf(sport, 16, "%d", Ntohs(inet->sport));
                snprintf(dport, 16, "%d", Ntohs(inet->dport));
                flag = 1;
            }
#endif
            break;
#if IS_ENABLED(CONFIG_IPV6)
            case AF_INET6:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
                if (likely(inet->inet_dport)) {
                    snprintf(dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_daddr));
                    snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_rcv_saddr));
                    snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                    snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                    flag = 1;
                }
#else
                if (likely(inet->dport)) {
                    snprintf(dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(inet->pinet6->daddr));
                    snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(inet->pinet6->saddr));
                    snprintf(sport, 16, "%d", Ntohs(inet->sport));
                    snprintf(dport, 16, "%d", Ntohs(inet->dport));
                    flag = 1;
                }
#endif
                break;
#endif
        default:
            break;
    }

    if (connect_dip_check(dip) == 1)
        goto out;

    if (flag == 1) {
        sessionid = get_sessionid();
        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);

        if (unlikely(!buffer))
            abs_path = "-2";
        else
            abs_path = get_exe_file(current, buffer, PATH_MAX);

        if (strlen(current->comm) > 0) {
            comm = str_replace(current->comm, "\n", " ");
            if (likely(comm))
                comm_free = 1;
            else
                comm = "";
        } else
            comm = "";

        result_str_len = strlen(current->nsproxy->uts_ns->name.nodename) +
                         strlen(comm) + strlen(abs_path) + 172;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);
        if (likely(result_str)) {
            snprintf(result_str, result_str_len,
                     "%d\n%s\n%d\n%d\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%s\n%s\n%d\n%u",
                     get_current_uid(), CONNECT_TYPE, data->sa_family,
                     data->type, dport, dip, abs_path,
                     current->pid, current->real_parent->pid,
                     pid_vnr(task_pgrp(current)), current->tgid,
                     comm, current->nsproxy->uts_ns->name.nodename,
                     sip, sport, retval, sessionid);

            send_msg_to_user(result_str, 1);
        }

        if (likely(strcmp(abs_path, "-2")))
            kfree(buffer);

        if (likely(comm_free == 1))
            kfree(comm);
    }

    return 0;

    out:
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
struct execve_data {
    char *abs_path;
    char *argv;
    char *ssh_connection;
    char *ld_preload;

    int free_abs_path;
    int free_ssh_connection;
    int free_ld_preload;
    int free_argv;
};

void get_execve_data(struct user_arg_ptr argv_ptr, struct user_arg_ptr env_ptr, const char __user * elf_path, struct execve_data *data) {
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, error = 0;
    int env_len = 0;
    int free_argv = 0;
    int free_abs_path = 0;
    int free_ld_preload = 1;
    int free_ssh_connection = 1;
    int ssh_connection_flag = 0;
    int ld_preload_flag = 0;
    char *tmp_buf = "0";
    char *exe_file_buf = "-2";
    char *argv_res = NULL;
    char *abs_path = NULL;
    char *argv_res_tmp = NULL;
    char *ssh_connection = NULL;
    char *ld_preload = NULL;
    const char __user *native;
    struct path exe_file;

    env_len = count(env_ptr, MAX_ARG_STRINGS);
    argv_len = count(argv_ptr, MAX_ARG_STRINGS);
    argv_res_len = 128 * (argv_len + 2);

    if(likely(argv_len > 0)) {
        argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
        if(unlikely(!argv_res))
            argv_res = NULL;
        else {
            for (i = 0; i < argv_len; i++) {
                native = get_user_arg_ptr(argv_ptr, i);
                if (unlikely(IS_ERR(native)))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if (unlikely(!len))
                    break;

                if (offset + len > argv_res_len - 1)
                    break;

                if (unlikely(copy_from_user(argv_res + offset, native, len)))
                    break;

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }
    }

    if (likely(argv_res)) {
        argv_res_tmp = str_replace(argv_res, "\n", " ");
        if(likely(argv_res_tmp))
            free_argv = 1;
        else
            argv_res_tmp = "";
    } else
        argv_res_tmp = "";

    ssh_connection = kzalloc(255, GFP_ATOMIC);
    ld_preload = kzalloc(255, GFP_ATOMIC);

    if(unlikely(!ssh_connection))
        free_ssh_connection = 0;

    if(unlikely(!ld_preload))
        free_ld_preload = 0;

    if(likely(env_len > 0)) {
        char buf[256];
        for (i = 0; i < env_len; i++) {
            native = get_user_arg_ptr(env_ptr, i);
            if (unlikely(IS_ERR(native)))
                continue;

            len = strnlen_user(native, MAX_ARG_STRLEN);
            if(unlikely(!len))
                continue;
            else if(len > 14) {
                memset(buf, 0, 255);
                if (unlikely(copy_from_user(buf, native, 255)))
                    break;
                else {
                    if(strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                        if(likely(free_ssh_connection == 1)) {
                            strcpy(ssh_connection, buf + 15);
                            ssh_connection_flag = 1;
                        } else
                            ssh_connection = "-1";
                    } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                        if (likely(free_ld_preload == 1)) {
                            strcpy(ld_preload, buf + 11);
                            ld_preload_flag = 1;
                        } else
                            ld_preload = "-1";
                    }
                }
            }
        }
    }

    if(unlikely(ssh_connection_flag == 0)) {
        if(unlikely(free_ssh_connection == 0))
            ssh_connection = "-1";
        else
            strcpy(ssh_connection, "-1");
    }
    data->ssh_connection = ssh_connection;
    data->free_ssh_connection = free_ssh_connection;

    if(unlikely(ld_preload_flag == 0)) {
        if(unlikely(free_ld_preload== 0))
            ld_preload = "-1";
        else
            strcpy(ld_preload, "-1");
    }
    data->ld_preload = ld_preload;
    data->free_ld_preload = free_ld_preload;

    tmp_buf = kzalloc(256, GFP_ATOMIC);
    if(unlikely(!tmp_buf))
        abs_path = "-2";
    else {
        if(unlikely(IS_ERR_OR_NULL(elf_path)))
            abs_path = "-1";
        if(unlikely(copy_from_user(tmp_buf, elf_path, 256)))
            abs_path = "-1";
        else {
            if(unlikely(strcmp(tmp_buf, "/") != 0 && strcmp(tmp_buf, ".") != 0)) {
                abs_path = tmp_buf;
                free_abs_path = 1;
            } else {
                error = kern_path(tmp_buf, LOOKUP_FOLLOW, &exe_file);
                if (unlikely(error))
                    abs_path = "-1";
                else {
                    exe_file_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
                    if (unlikely(!exe_file_buf))
                        abs_path = "-2";
                    else {
                        abs_path = d_path(&exe_file, exe_file_buf, PATH_MAX);
                        if (unlikely(IS_ERR(abs_path)))
                            abs_path = "-1";
                        kfree(exe_file_buf);
                    }
                    path_put(&exe_file);
                }
            }
        }
    }

    data->argv = argv_res_tmp;
    data->abs_path = abs_path;
    data->free_abs_path = free_abs_path;
    data->free_argv = free_argv;

    if(likely(argv_res))
        kfree(argv_res);
}

#ifdef CONFIG_COMPAT
int compat_execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        struct user_arg_ptr argv_ptr = {
            .is_compat = true,
            .ptr.compat = (const compat_uptr_t __user *)p_get_arg2(regs),
        };

        struct user_arg_ptr env_ptr = {
            .is_compat = true,
            .ptr.compat = (const compat_uptr_t __user *)p_get_arg3(regs),
        };

        get_execve_data(argv_ptr, env_ptr, (const char __user *)p_get_arg1(regs), (struct execve_data *)ri->data);
    }
    return 0;
}

int compat_execveat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        struct user_arg_ptr argv_ptr = {
            .is_compat = true,
            .ptr.compat = (const compat_uptr_t __user *)p_get_arg3(regs),
        };

        struct user_arg_ptr env_ptr = {
            .is_compat = true,
            .ptr.compat = (const compat_uptr_t __user *)p_get_arg4(regs),
        };

        get_execve_data(argv_ptr, env_ptr, (const char __user *)p_get_arg1(regs), (struct execve_data *)ri->data);
    }
    return 0;
}
#endif

int execveat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        struct user_arg_ptr argv_ptr = {.ptr.native = (const char * const*) p_get_arg3(regs)};
        struct user_arg_ptr env_ptr = {.ptr.native = (const char * const*) p_get_arg4(regs)};
        get_execve_data(argv_ptr, env_ptr, (const char __user *)p_get_arg1(regs), (struct execve_data *)ri->data);
    }
    return 0;
}

int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        struct user_arg_ptr argv_ptr = {.ptr.native = (const char * const*) p_get_arg2(regs)};
        struct user_arg_ptr env_ptr = {.ptr.native = (const char * const*) p_get_arg3(regs)};
        get_execve_data(argv_ptr, env_ptr, (const char __user *)p_get_arg1(regs), (struct execve_data *)ri->data);
    }
    return 0;
}

int execve_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int result_str_len;
    unsigned int sessionid;
    char *result_str = NULL;
    char *abs_path = NULL;
    char *pname = NULL;
    char *tmp_stdin = NULL;
    char *tmp_stdout = NULL;
    char *argv = NULL;
    char *comm = NULL;

    if (share_mem_flag != -1) {
        int i;
        int comm_free = 0;
        int pid_tree_free = 0;
        int limit_index = 0;
        int free_abs_path;
        void *tmp_socket = NULL;
        pid_t socket_pid = -1;
        int socket_check = 0;
        int tty_name_len = 0;
        const char *d_name = "-1";
        int sa_family = -1;
        char *nodename = "-1";
        char *pid_tree = "-1";
        char *socket_pname = "-1";
        char *socket_pname_buf = "-2";
        struct execve_data *data;
        struct fdtable *files;
        struct socket *socket;
        struct fdtable *task_files;
        struct task_struct *task;
        char dip[64] = "-1";
        char sip[64] = "-1";
        char dport[16] = "-1";
        char sport[16] = "-1";
        struct sock *sk;
        struct inet_sock *inet;
        struct tty_struct *tty;
        char fd_buff[24];
        char stdin_fd_buf[PATH_MAX];
        char stdout_fd_buf[PATH_MAX];
        char *tty_name = "-1";

        memset(fd_buff, 0, 24);
        memset(stdin_fd_buf, 0, PATH_MAX);
        memset(stdout_fd_buf, 0, PATH_MAX);

        data = (struct execve_data *)ri->data;
        argv = data->argv;
        abs_path = data->abs_path;
        free_abs_path = data->free_abs_path;

        if(execve_exe_check(abs_path) == 1) {
            if (likely(data->free_abs_path == 1))
                kfree(data->abs_path);

            if(likely(data->free_argv == 1))
                kfree(data->argv);

            if(likely(data->free_ld_preload == 1))
                kfree(data->ld_preload);

            if(likely(data->free_ssh_connection == 1))
                kfree(data->ssh_connection);

            return 0;
        }

        sessionid = get_sessionid();
        tty = get_current_tty();

        if(likely(current->nsproxy->uts_ns))
            nodename = current->nsproxy->uts_ns->name.nodename;

        if(likely(current->comm)) {
            if(likely(strlen(current->comm)) > 0) {
                comm = str_replace(current->comm, "\n", " ");
                if(likely(comm))
                    comm_free = 1;
                else
                    comm = "";
            } else
                comm = "";
        } else
            comm = "";

        tty = get_current_tty();
        if(likely(tty)) {
            if(likely(tty->name)) {
                tty_name_len = strlen(tty->name);
                if(tty_name_len == 0)
                    tty_name = "-1";
                else
                    tty_name = tty->name;
            } else
                tty_name = "-1";
        } else
            tty_name = "-1";

        task = current;
        while(task->pid != 1) {
            limit_index = limit_index + 1;
            if(limit_index > EXECVE_GET_SOCK_PPID_LIMIT)
                break;

            if(unlikely(!task->files))
                continue;

            task_files = files_fdtable(task->files);

            for (i = 0; task_files->fd[i]; i++) {
                if(i > EXECVE_GET_SOCK_FD_LIMIT)
                    break;

                d_name = d_path(&(task_files->fd[i]->f_path), fd_buff, 24);
                if (IS_ERR(d_name)) {
                    d_name = "-1";
                    continue;
                }

                if(strncmp("socket:[", d_name, 8) == 0) {
                    if(unlikely(!task_files->fd[i] || IS_ERR(task_files->fd[i]->private_data)))
                        continue;

                    tmp_socket = task_files->fd[i]->private_data;

                    socket = (struct socket *)tmp_socket;
                    if(likely(socket)) {
                        sk = socket->sk;
                        if(unlikely(!socket->sk))
                            continue;

                        inet = (struct inet_sock*)sk;
                        sa_family = sk->sk_family;
                        switch (sk->sk_family) {
                            case AF_INET:
                                snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_daddr));
                                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_saddr));
                                snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                                snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                                socket_check = 1;
                                break;
#if IS_ENABLED(CONFIG_IPV6)
                            case AF_INET6:
                                snprintf(dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_daddr));
                                snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_rcv_saddr));
                                snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                                snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                                socket_check = 1;
                                break;
#endif
                        }
                    }
                }
            }

            if (socket_check == 1) {
                pid_tree = get_pid_tree();
                if(unlikely(!pid_tree))
                    pid_tree = "-1";
                else
                    pid_tree_free = 1;

                socket_pid = task->pid;
                socket_pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
                if (unlikely(!socket_pname_buf))
                    socket_pname = "-2";
                else {
                    socket_pname = get_exe_file(task, socket_pname_buf, PATH_MAX);
                    if (unlikely(!socket_pname))
                        socket_pname = "-1";
                }
                break;
            } else
                task = task->parent;
        }

        files = files_fdtable(current->files);
        if(likely(files->fd[0])) {
            tmp_stdin = d_path(&(files->fd[0]->f_path), stdin_fd_buf, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdin)))
                tmp_stdin = "-1";
        } else
            tmp_stdin = "";

        if(likely(files->fd[1])) {
            tmp_stdout = d_path(&(files->fd[1]->f_path), stdout_fd_buf, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdout)))
                tmp_stdout = "-1";
        } else
            tmp_stdout = "";

        pname = _dentry_path_raw();

        result_str_len = strlen(argv) + strlen(pname) + strlen(abs_path) + strlen(pid_tree) + tty_name_len +
                         strlen(comm) + strlen(nodename) + strlen(data->ssh_connection) +
                         strlen(data->ld_preload) + 256;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);

        if(likely(result_str)) {
            snprintf(result_str, result_str_len,
                 "%d\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%s\n%s\n%u\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n%d\n%s\n%s\n%s",
                 get_current_uid(), EXECVE_TYPE, pname,
                 abs_path, argv, current->pid,
                 current->real_parent->pid, pid_vnr(task_pgrp(current)),
                 current->tgid, comm,
                 nodename, tmp_stdin, tmp_stdout,
                 sessionid, dip, dport, sip, sport, sa_family,
                 pid_tree, tty_name, socket_pid, socket_pname,
                 data->ssh_connection, data->ld_preload);

            send_msg_to_user(result_str, 1);
        }

        if (likely(strcmp(socket_pname_buf, "-2")))
            kfree(socket_pname_buf);

        if (likely(free_abs_path == 1))
            kfree(data->abs_path);

        if(likely(comm_free == 1))
            kfree(comm);

        if(likely(data->free_argv == 1))
            kfree(data->argv);

        if(pid_tree_free == 1)
            kfree(pid_tree);

        if(likely(data->free_ld_preload == 1))
            kfree(data->ld_preload);

        if(likely(data->free_ssh_connection == 1))
            kfree(data->ssh_connection);
    }
    return 0;
}
#else

struct execve_data {
    char *argv;
    char *ssh_connection;
    char *ld_preload;

    int free_argv;
    int free_ssh_connection;
    int free_ld_preload;
};

void get_execve_data(char **argv, char **env, struct execve_data *data) {
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0;
    int env_len = 0;
    int free_argv = 0;
    int ssh_connection_flag = 0;
    int free_ssh_connection = 1;
    int free_ld_preload = 1;
    int ld_preload_flag = 0;
    char *argv_res = NULL;
    char *argv_res_tmp = NULL;
    char *ssh_connection = NULL;
    char *ld_preload = NULL;
    const char __user
    *native;

    env_len = count(env, MAX_ARG_STRINGS);
    argv_res_len = 128 * (argv_len + 2);
    argv_len = count(argv, MAX_ARG_STRINGS);

    if (likely(argv_len > 0)) {
        argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
        if (likely(argv_res)) {
            for (i = 0; i < argv_len; i++) {
                if (get_user(native, argv + i))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if (!len)
                    break;

                if (offset + len > argv_res_len - 1)
                    break;

                if (copy_from_user(argv_res + offset, native, len))
                    break;

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        } else {
            argv_res = NULL;
        }
    }

    if (likely(argv_res)) {
        argv_res_tmp = str_replace(argv_res, "\n", " ");
        if (likely(argv_res_tmp))
            free_argv = 1;
        else
            argv_res_tmp = "";
    } else
        argv_res_tmp = "";

    ssh_connection = kzalloc(255, GFP_ATOMIC);
    ld_preload = kzalloc(255, GFP_ATOMIC);

    if (unlikely(!ssh_connection))
        free_ssh_connection = 0;

    if (unlikely(!ld_preload))
        free_ld_preload = 0;


    if (likely(env_len > 0)) {
        char buf[256];
        for (i = 0; i < argv_len; i++) {
            if (get_user(native, env + i))
                break;

            len = strnlen_user(native, MAX_ARG_STRLEN);
            if (!len)
                break;
            else if (len > 14) {
                memset(buf, 0, 255);
                if (copy_from_user(buf, native, 255))
                    break;
                else {
                    if (strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                        if (likely(free_ssh_connection == 1)) {
                            strcpy(ssh_connection, buf + 15);
                            ssh_connection_flag = 1;
                        } else
                            ssh_connection = "-1";
                    } else if (strncmp("LD_PRELOAD=", buf, 11) == 0) {
                        if (likely(free_ld_preload == 1)) {
                            strcpy(ld_preload, buf + 11);
                            ld_preload_flag = 1;
                        } else
                            ld_preload = "-1";
                    }
                }
            }
        }
    }

    if (unlikely(ssh_connection_flag == 0)) {
        if (unlikely(free_ssh_connection == 0))
            ssh_connection = "-1";
        else
            strcpy(ssh_connection, "-1");
    }
    data->ssh_connection = ssh_connection;
    data->free_ssh_connection = free_ssh_connection;

    if (unlikely(ld_preload_flag == 0)) {
        if (unlikely(free_ld_preload == 0))
            ld_preload = "-1";
        else
            strcpy(ld_preload, "-1");
    }
    data->ld_preload = ld_preload;
    data->free_ld_preload = free_ld_preload;

    data->argv = argv_res_tmp;
    data->free_argv = free_argv;

    if (likely(argv_res))
        kfree(argv_res);
}

int compat_execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    if (share_mem_flag != -1) {
        char **argv = (char **) p_get_arg2(regs);
        char **env = (char **) p_get_arg3(regs);
        get_execve_data(argv, env, (struct execve_data *) ri->data);
    }
    return 0;
}

int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    if (share_mem_flag != -1) {
        char **argv = (char **) p_get_arg2(regs);
        char **env = (char **) p_get_arg3(regs);
        get_execve_data(argv, env, (struct execve_data *) ri->data);
    }
    return 0;
}

int execve_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int result_str_len;
    unsigned int sessionid;
    char *result_str = NULL;
    char *pname = NULL;
    char *tmp_stdin = NULL;
    char *tmp_stdout = NULL;
    char *comm = NULL;
    char *buffer = NULL;

    if (share_mem_flag != -1) {
        pid_t socket_pid = -1;
        int i;
        int limit_index = 0;
        int comm_free = 0;
        int pid_tree_free = 0;
        int socket_check = 0;
        int tty_name_len = 0;
        void *tmp_socket = NULL;
        char *pid_tree = "-1";
        char *nodename = "-1";
        char *socket_pname = "-1";
        char *socket_pname_buf = "-2";
        const char *d_name = "-1";
        int sa_family = -1;
        char *argv = NULL;
        char *abs_path = NULL;
        char fd_buff[24];
        char tmp_stdin_fd[PATH_MAX];
        char tmp_stdout_fd[PATH_MAX];
        struct fdtable *files;
        struct execve_data *data;
        struct socket *socket;
        struct tty_struct *tty;
        struct fdtable *task_files;
        struct task_struct *task;
        char dip[64] = "-1";
        char sip[64] = "-1";
        char dport[16] = "-1";
        char sport[16] = "-1";
        char *tty_name = "-1";
        struct sock *sk;
        struct inet_sock *inet;

        memset(fd_buff, 0, 24);
        memset(tmp_stdin_fd, 0, PATH_MAX);
        memset(tmp_stdout_fd, 0, PATH_MAX);

        data = (struct execve_data *) ri->data;
        argv = data->argv;

        sessionid = get_sessionid();

        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        if (unlikely(!buffer))
            abs_path = "-2";
        else {
            abs_path = get_exe_file(current, buffer, PATH_MAX);
            if (execve_exe_check(abs_path) == 1) {
                if (likely(strcmp(buffer, "-2")))
                    kfree(buffer);

                if (likely(data->free_argv == 1))
                    kfree(data->argv);

                if (likely(data->free_ld_preload == 1))
                    kfree(data->ld_preload);

                if (likely(data->free_ssh_connection == 1))
                    kfree(data->ssh_connection);
                return 0;
            }
        }

        if (likely(current->nsproxy->uts_ns))
            nodename = current->nsproxy->uts_ns->name.nodename;

        if (likely(current->comm)) {
            if (likely(strlen(current->comm)) > 0) {
                comm = str_replace(current->comm, "\n", " ");
                if (likely(comm))
                    comm_free = 1;
                else
                    comm = "";
            } else
                comm = "";
        } else
            comm = "";

        tty = get_current_tty();
        if (likely(tty)) {
            if (likely(tty->name)) {
                tty_name_len = strlen(tty->name);
                if (tty_name_len == 0)
                    tty_name = "-1";
                else
                    tty_name = tty->name;
            } else
                tty_name = "-1";
        } else
            tty_name = "-1";

        task = current;
        while (task->pid != 1) {
            limit_index = limit_index + 1;
            if (limit_index > EXECVE_GET_SOCK_LIMIT)
                break;

            if (unlikely(!task->files))
                continue;

            task_files = files_fdtable(task->files);

            for (i = 0; task_files->fd[i]; i++) {
                if (i > 7)
                    break;

                d_name = d_path(&(task_files->fd[i]->f_path), fd_buff, 24);
                if (IS_ERR(d_name)) {
                    d_name = "-1";
                    continue;
                }

                if (strncmp("socket:[", d_name, 8) == 0) {
                    if (unlikely(!task_files->fd[i] || IS_ERR(task_files->fd[i]->private_data)))
                        continue;

                    tmp_socket = task_files->fd[i]->private_data
                    socket = (struct socket *) tmp_socket;
                    if (likely(socket)) {
                        sk = socket->sk;
                        if (unlikely(!socket->sk))
                            continue;

                        inet = (struct inet_sock *) sk;
                        sa_family = sk->sk_family;
                        switch (sk->sk_family) {
                            case AF_INET:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
                                snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_daddr));
                                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_saddr));
                                snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                                snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
#else
                                snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->daddr));
                                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->saddr));
                                snprintf(sport, 16, "%d", Ntohs(inet->sport));
                                snprintf(dport, 16, "%d", Ntohs(inet->dport));
#endif
                                socket_check = 1;
                                break;
#if IS_ENABLED(CONFIG_IPV6)
                                case AF_INET6:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
                                    snprintf(dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_daddr));
                                    snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_rcv_saddr));
                                    snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                                    snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
#else
                                    snprintf(dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(inet->pinet6->daddr));
                                    snprintf(sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(inet->pinet6->saddr));
                                    snprintf(sport, 16, "%d", Ntohs(inet->sport));
                                    snprintf(dport, 16, "%d", Ntohs(inet->dport));
#endif
                                    socket_check = 1;
                                    break;
#endif
                        }
                    }
                }
            }

            if (socket_check == 1) {
                pid_tree = get_pid_tree();
                if (unlikely(!pid_tree))
                    pid_tree = "-1";
                else
                    pid_tree_free = 1;

                socket_pid = task->pid;
                socket_pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
                if (unlikely(!socket_pname_buf))
                    socket_pname = "-2";
                else {
                    socket_pname = get_exe_file(task, socket_pname_buf, PATH_MAX);
                    if (unlikely(!socket_pname))
                        socket_pname = "-1";
                }
                break;
            } else
                task = task->parent;
        }

        files = files_fdtable(current->files);
        if (likely(files->fd[0])) {
            tmp_stdin = d_path(&(files->fd[0]->f_path), tmp_stdin_fd, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdin)))
                tmp_stdin = "-1";
        } else
            tmp_stdin = "";

        if (likely(files->fd[1])) {
            tmp_stdout = d_path(&(files->fd[1]->f_path), tmp_stdout_fd, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdout)))
                tmp_stdout = "-1";
        } else
            tmp_stdout = "";

        pname = _dentry_path_raw();

        result_str_len = strlen(argv) + strlen(pname) +
                         strlen(abs_path) + strlen(comm) + strlen(pid_tree) + tty_name_len +
                         strlen(nodename) + strlen(data->ssh_connection) +
                         strlen(data->ld_preload) + 256;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);
        if (likely(result_str)) {
            snprintf(result_str, result_str_len,
                     "%d\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%s\n%s\n%u\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n%d\n%s\n%s\n%s",
                     get_current_uid(), EXECVE_TYPE, pname,
                     abs_path, argv, current->pid,
                     current->real_parent->pid, pid_vnr(task_pgrp(current)),
                     current->tgid, comm,
                     nodename, tmp_stdin, tmp_stdout,
                     sessionid, dip, dport, sip, sport, sa_family,
                     pid_tree, tty_name, socket_pid, socket_pname,
                     data->ssh_connection, data->ld_preload);

            send_msg_to_user(result_str, 1);
        }

        if (likely(strcmp(buffer, "-2")))
            kfree(buffer);

        if (likely(strcmp(socket_pname_buf, "-2")))
            kfree(socket_pname_buf);

        if (likely(comm_free == 1))
            kfree(comm);

        if (likely(data->free_argv == 1))
            kfree(data->argv);

        if (pid_tree_free == 1)
            kfree(pid_tree);

        if (likely(data->free_ld_preload == 1))
            kfree(data->ld_preload);

        if (likely(data->free_ssh_connection == 1))
            kfree(data->ssh_connection);
    }

    return 0;
}

#endif

int security_inode_create_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int result_str_len;
    int comm_free = 0;
    unsigned int sessionid;
    void *tmp;
    char *result_str = NULL;
    char *comm = NULL;
    char *pname_buf = NULL;
    char *buffer = NULL;
    char *pathstr = NULL;
    char *abs_path = NULL;

    if (share_mem_flag == -1)
        return 0;

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);

    if (unlikely(!pname_buf)) {
        pname_buf = "-2";
        pathstr = "-2";
    } else {
        tmp = (void *) p_regs_get_arg2(regs);
        if(unlikely(IS_ERR_OR_NULL(tmp))) {
            if (likely(strcmp(pname_buf, "-2")))
                kfree(pname_buf);
            return 0;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw((struct dentry *) tmp, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path((struct dentry *) tmp, pname_buf, PATH_MAX);
#endif
    }

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!buffer))
        abs_path = "-2";
    else
        abs_path = get_exe_file(current, buffer, PATH_MAX);

    sessionid = get_sessionid();

    if (strlen(current->comm) > 0) {
        comm = str_replace(current->comm, "\n", " ");
        if (likely(comm))
            comm_free = 1;
        else
            comm = "";
    } else
        comm = "";

    result_str_len = strlen(current->nsproxy->uts_ns->name.nodename)
                     + strlen(comm) + strlen(abs_path) + 172;
    if (likely(pathstr))
        result_str_len = result_str_len + strlen(pathstr);
    else
        pathstr = "";

    result_str = kzalloc(result_str_len, GFP_ATOMIC);
    if (likely(result_str)) {
        snprintf(result_str, result_str_len,
                 "%d\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%u",
                 get_current_uid(), CREATE_FILE, abs_path, pathstr,
                 current->pid, current->real_parent->pid,
                 pid_vnr(task_pgrp(current)), current->tgid,
                 comm, current->nsproxy->uts_ns->name.nodename, sessionid);
        send_msg_to_user(result_str, 1);
    }

    if (likely(strcmp(pname_buf, "-2")))
        kfree(pname_buf);

    if (likely(strcmp(abs_path, "-2")))
        kfree(buffer);

    if (likely(comm_free == 1))
        kfree(comm);

    return 0;
}

void ptrace_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    int result_str_len;
    int comm_free = 0;
    long request;
    long pid;
    void *addr;
    char *data;
    void *data_tmp;
    char *abs_path = NULL;
    char *result_str = NULL;
    char *comm = NULL;
    char *buffer = NULL;
    unsigned int sessionid;

    request = (long) p_get_arg1(regs);

    if (share_mem_flag == -1)
        return;

    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        pid = (long) p_get_arg2(regs);
        addr = (void *) p_get_arg3(regs);
        data_tmp = (void *) p_get_arg4(regs);
        if(unlikely(IS_ERR_OR_NULL(data_tmp)))
            return;
        else
            data = (char *) p_get_arg4(regs);

        sessionid = get_sessionid();

        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        if (unlikely(!buffer))
            abs_path = "-2";
        else
            abs_path = get_exe_file(current, buffer, PATH_MAX);

        if (strlen(current->comm) > 0) {
            comm = str_replace(current->comm, "\n", " ");
            if (likely(comm))
                comm_free = 1;
            else
                comm = "";
        } else
            comm = "";

        result_str_len = strlen(current->nsproxy->uts_ns->name.nodename) +
                         strlen(comm) + strlen(abs_path) + 172;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);

        if (likely(result_str)) {
            snprintf(result_str, result_str_len,
                     "%d\n%s\n%ld\n%ld\n%p\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%u",
                     get_current_uid(), PTRACE_TYPE, request,
                     pid, addr, &data, abs_path,
                     current->pid, current->real_parent->pid,
                     pid_vnr(task_pgrp(current)), current->tgid,
                     comm, current->nsproxy->uts_ns->name.nodename, sessionid);
            send_msg_to_user(result_str, 1);
        }

        if (likely(strcmp(abs_path, "-2")))
            kfree(buffer);

        if (likely(comm_free == 1))
            kfree(comm);
    }
}

void dns_data_transport(int sa_family, char *query, char dip[64], char sip[64], char dport[16], char sport[16], int qr,
                        int opcode, int rcode) {
    int comm_free = 0;
    int result_str_len;
    unsigned int sessionid;
    char *comm = NULL;
    char *abs_path = NULL;
    char *result_str = NULL;
    char *buffer = NULL;
    char *nodename = "-1";

    if (connect_dip_check(dip) == 1) {
        kfree(query);
        return;
    }

    sessionid = get_sessionid();
    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!buffer))
        abs_path = "-2";
    else
        abs_path = get_exe_file(current, buffer, PATH_MAX);

    if (strlen(current->comm) > 0) {
        comm = str_replace(current->comm, "\n", " ");
        if (likely(comm))
            comm_free = 1;
        else
            comm = "";
    } else
        comm = "";

    if (likely(current->nsproxy->uts_ns))
        nodename = current->nsproxy->uts_ns->name.nodename;

    result_str_len = strlen(query) + strlen(nodename) +
                     strlen(comm) + strlen(abs_path) + 172;

    result_str = kzalloc(result_str_len, GFP_ATOMIC);
    if (likely(result_str)) {
        snprintf(result_str, result_str_len,
                 "%d\n%s\n%d\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%s\n%u",
                 get_current_uid(), DNS_TYPE, sa_family,
                 dport, dip, abs_path,
                 current->pid, current->real_parent->pid,
                 pid_vnr(task_pgrp(current)), current->tgid,
                 comm, nodename,
                 sip, sport, qr, opcode, rcode,
                 query, sessionid);

        send_msg_to_user(result_str, 1);
    }

    if (likely(query))
        kfree(query);

    if (likely(strcmp(abs_path, "-2")))
        kfree(buffer);

    if (likely(comm_free == 1))
        kfree(comm);
}

int udp_recvmsg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct sock *sk;
    struct inet_sock *inet;
    struct msghdr *msg;
    struct udp_recvmsg_data *data;
    void *tmp_msg;
    int flags;

    if (share_mem_flag == -1)
        return 0;

    data = (struct udp_recvmsg_data *) ri->data;
    data->flag = 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    flags = (int) p_get_arg5(regs);
#else
    flags = (int) p_get_arg6(regs);
#endif
    if (flags & MSG_ERRQUEUE)
        return 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    sk = (struct sock *) p_get_arg1(regs);
#else
    sk = (struct sock *) p_get_arg2(regs);
#endif
    if(unlikely(IS_ERR_OR_NULL(sk)))
        return 0;

    inet = (struct inet_sock *) sk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
    if (inet->inet_dport == 13568 || inet->inet_dport == 59668)
#else
    if (inet->dport == 13568 || inet->dport == 59668)
#endif
    {
        data->sa_family = AF_INET;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
        if (likely(inet->inet_daddr)) {
            snprintf(data->dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_daddr));
            snprintf(data->sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_saddr));
            snprintf(data->sport, 16, "%d", Ntohs(inet->inet_sport));
            snprintf(data->dport, 16, "%d", Ntohs(inet->inet_dport));
        }
#else
        if (likely(inet->daddr)) {
            snprintf(data->dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->daddr));
            snprintf(data->sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->saddr));
            snprintf(data->sport, 16, "%d", Ntohs(inet->sport));
            snprintf(data->dport, 16, "%d", Ntohs(inet->dport));
        }
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
        tmp_msg = (void *) p_get_arg2(regs);
#else
        tmp_msg = (void *) p_get_arg3(regs);
#endif
        if (IS_ERR_OR_NULL(tmp_msg))
            return 0;

        msg = (struct msghdr *) tmp_msg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        if(msg->msg_iter.iov) {
            if(msg->msg_iter.iov->iov_len > 0) {
                data->iov_len = msg->msg_iter.iov->iov_len;
                data->iov_base = msg->msg_iter.iov->iov_base;
            } else
                return 0;
        } else if(msg->msg_iter.kvec) {
            if(msg->msg_iter.kvec->iov_len > 0) {
                data->iov_len = msg->msg_iter.kvec->iov_len;
                data->iov_base = msg->msg_iter.kvec->iov_base;
            } else
                return 0;
        } else
            return 0;
#else
        if (data->iov_len > 0) {
            data->iov_base = msg->msg_iov->iov_base;
            data->iov_len = msg->msg_iov->iov_len;
        } else
            return 0;

        data->flag = 1;
#endif
    }

    return 0;
}

int udpv6_recvmsg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct sock *sk;
    struct inet_sock *inet;
    struct msghdr *msg;
    struct udp_recvmsg_data *data;
    void *tmp_msg;
    int flags;

    if (share_mem_flag == -1)
        return 0;

    data = (struct udp_recvmsg_data *) ri->data;
    data->flag = 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    flags = (int) p_get_arg5(regs);
#else
    flags = (int) p_get_arg6(regs);
#endif
    if (flags & MSG_ERRQUEUE)
        return 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    sk = (struct sock *) p_get_arg1(regs);
#else
    sk = (struct sock *) p_get_arg2(regs);
#endif

    if(unlikely(IS_ERR_OR_NULL(sk)))
        return 0;

    inet = (struct inet_sock *) sk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
    if (inet->inet_dport == 13568 || inet->inet_dport == 59668)
#else
    if (inet->dport == 13568 || inet->dport == 59668)
#endif
    {
        data->sa_family = AF_INET;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
        if (likely(inet->inet_dport)) {
            snprintf(data->dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_daddr));
            snprintf(data->sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(sk->sk_v6_rcv_saddr));
            snprintf(data->sport, 16, "%d", Ntohs(inet->inet_sport));
            snprintf(data->dport, 16, "%d", Ntohs(inet->inet_dport));
        }
#else
        if (likely(inet->dport)) {
            snprintf(data->dip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(inet->pinet6->daddr));
            snprintf(data->sip, 64, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", NIP6(inet->pinet6->saddr));
            snprintf(data->sport, 16, "%d", Ntohs(inet->sport));
            snprintf(data->dport, 16, "%d", Ntohs(inet->dport));
        }
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
        tmp_msg = (void *) p_get_arg2(regs);
#else
        tmp_msg = (void *) p_get_arg3(regs);
#endif
        if (IS_ERR_OR_NULL(tmp_msg))
            return 0;

        msg = (struct msghdr *) tmp_msg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        if(msg->msg_iter.iov) {
            if(msg->msg_iter.iov->iov_len > 0) {
                data->iov_len = msg->msg_iter.iov->iov_len;
                data->iov_base = msg->msg_iter.iov->iov_base;
            } else
                return 0;
        } else if(msg->msg_iter.kvec) {
            if(msg->msg_iter.kvec->iov_len > 0) {
                data->iov_len = msg->msg_iter.kvec->iov_len;
                data->iov_base = msg->msg_iter.kvec->iov_base;
            } else
                return 0;
        } else
            return 0;
#else
        if (data->iov_len > 0) {
            data->iov_base = msg->msg_iov->iov_base;
            data->iov_len = msg->msg_iov->iov_len;
        } else
            return 0;

        data->flag = 1;
#endif
    }

    return 0;
}

int udp_recvmsg_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int opcode = 0;
    int qr;
    int rcode = 0;
    int recv_data_copy_res = 0;
    char *query;
    unsigned char *recv_data = NULL;
    struct udp_recvmsg_data *data;

    if (share_mem_flag == -1)
        return 0;

    data = (struct udp_recvmsg_data *) ri->data;
    if (data->flag != 1)
        return 0;

    if (data->iov_len > 0)
        recv_data = kzalloc(data->iov_len, GFP_ATOMIC);
    else
        return 0;

    if (unlikely(!recv_data))
        return 0;
    else
        recv_data_copy_res = copy_from_user(recv_data, data->iov_base, data->iov_len);

    if (unlikely(recv_data_copy_res != 0)) {
        kfree(recv_data);
        return 0;
    }

    if (sizeof(recv_data) >= 8) {
        qr = (recv_data[2] & 0x80) ? 1 : 0;
        if (qr == 1) {
            opcode = (recv_data[2] >> 3) & 0x0f;
            rcode = recv_data[3] & 0x0f;

            if (strlen(recv_data + 12) == 0) {
                kfree(recv_data);
                return 0;
            }

            query = kzalloc(strlen(recv_data + 12), GFP_ATOMIC);
            if (unlikely(IS_ERR_OR_NULL(query))) {
                kfree(recv_data);
                return 0;
            } else
                getDNSQuery(recv_data, 12, query);

            if (!query) {
                kfree(query);
                kfree(recv_data);
                return 0;
            }

            dns_data_transport(AF_INET6, query, data->dip, data->sip, data->dport, data->sport, qr, opcode, rcode);
        }
    }

    kfree(recv_data);
    return 0;
}

void load_module_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    int i = 0;
    int comm_free = 0;
    int result_str_len;
    unsigned int sessionid;
    char *cwd = NULL;
    char *result_str = NULL;
    char *comm = NULL;
    char *buffer = NULL;
    char *abs_path = NULL;
    char init_module_buf[PATH_MAX];
    struct path files_path;
    struct files_struct *current_files;
    struct fdtable *files_table;

    if (share_mem_flag == -1)
        return;

    memset(init_module_buf, 0, PATH_MAX);

    sessionid = get_sessionid();
    current_files = current->files;
    files_table = files_fdtable(current_files);

    while (files_table->fd[i])
        i++;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!buffer))
        abs_path = "-2";
    else
        abs_path = get_exe_file(current, buffer, PATH_MAX);

    files_path = files_table->fd[i - 1]->f_path;
    cwd = d_path(&files_path, init_module_buf, PATH_MAX);

    if (strlen(current->comm) > 0) {
        comm = str_replace(current->comm, "\n", " ");
        if (likely(comm))
            comm_free = 1;
        else
            comm = "";
    } else
        comm = "";

    result_str_len = strlen(cwd) + strlen(current->nsproxy->uts_ns->name.nodename)
                     + strlen(comm) + strlen(abs_path) + 192;

    result_str = kzalloc(result_str_len, GFP_ATOMIC);
    if (likely(result_str)) {
        snprintf(result_str, result_str_len, "%d\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%u",
                 get_current_uid(), LOAD_MODULE_TYPE, abs_path, cwd,
                 current->pid, current->real_parent->pid,
                 pid_vnr(task_pgrp(current)), current->tgid,
                 comm, current->nsproxy->uts_ns->name.nodename, sessionid);

        send_msg_to_user(result_str, 1);
    }

    if (likely(strcmp(abs_path, "-2")))
        kfree(buffer);
}

struct update_cred_data {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    uid_t old_uid;
#else
    int old_uid;
#endif
};

int update_cred_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    if (share_mem_flag != -1) {
        struct update_cred_data *data;
        data = (struct update_cred_data *) ri->data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
        data->old_uid = current->real_cred->uid.val;
#else
        data->old_uid = current->real_cred->uid;
#endif
    }
    return 0;
}

int update_cred_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int comm_free = 0;
    int now_uid;
    struct update_cred_data *data;
    char *comm = NULL;
    char *buffer = NULL;

    if (share_mem_flag == -1)
        return 0;

    now_uid = get_current_uid();

    if (now_uid != 0)
        return 0;

    data = (struct update_cred_data *) ri->data;
    if (data->old_uid != 0) {
        if (strlen(current->comm) > 0) {
            comm = str_replace(current->comm, "\n", " ");
            if (likely(comm))
                comm_free = 1;
            else
                comm = "";
        } else
            comm = "";

        if (strcmp(comm, "sudo") != 0 && strcmp(comm, "su") != 0 && strcmp(comm, "sshd") != 0) {
            int result_str_len;
            unsigned int sessionid;
            char *result_str = NULL;
            char *abs_path;

            buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
            if (unlikely(!buffer))
                abs_path = "-2";
            else
                abs_path = get_exe_file(current, buffer, PATH_MAX);

            sessionid = get_sessionid();

            result_str_len = strlen(current->nsproxy->uts_ns->name.nodename)
                             + strlen(comm) + strlen(abs_path) + 192;

            result_str = kzalloc(result_str_len, GFP_ATOMIC);
            if (likely(result_str)) {
                snprintf(result_str, result_str_len, "%d\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n%d\n%s\n%u",
                         get_current_uid(), UPDATE_CRED_TYPE, abs_path,
                         current->pid, current->real_parent->pid,
                         pid_vnr(task_pgrp(current)), current->tgid,
                         comm, data->old_uid, current->nsproxy->uts_ns->name.nodename,
                         sessionid);

                send_msg_to_user(result_str, 1);
            }

            if (likely(strcmp(abs_path, "-2")))
                kfree(buffer);

            if (likely(comm_free == 1))
                kfree(comm);
        }
    }
    return 0;
}

int tcp_v4_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct connect_data *data;
    if (share_mem_flag == -1)
        return 0;

    data = (struct connect_data *) ri->data;
    data->sk = (struct sock *) p_get_arg1(regs);
    data->sa_family = AF_INET;
    data->type = 4;
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
int tcp_v6_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct connect_data *data;
    if (share_mem_flag == -1)
        return 0;

    data = (struct connect_data *) ri->data;
    data->sa_family = AF_INET6;
    data->type = 6;
    data->sk = (struct sock *) p_get_arg1(regs);
    return 0;
}
#endif

int ip4_datagram_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct connect_data *data;
    if (share_mem_flag == -1)
        return 0;

    data = (struct connect_data *) ri->data;
    data->sa_family = AF_INET;
    data->type = 4;
    data->sk = (struct sock *) p_get_arg1(regs);
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
int ip6_datagram_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct connect_data *data;
    if (share_mem_flag == -1)
        return 0;

    data = (struct connect_data *) ri->data;
    data->sa_family = AF_INET6;
    data->type = 6;
    data->sk = (struct sock *) p_get_arg1(regs);
    return 0;
}
#endif

struct kretprobe bind_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(bind),
        .data_size  = sizeof(struct bind_data),
        .handler = bind_handler,
        .entry_handler = bind_entry_handler,
        .maxactive = MAXACTIVE,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
struct kretprobe execveat_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
    .data_size  = sizeof(struct execve_data),
    .handler = execve_handler,
    .entry_handler = execveat_entry_handler,
    .maxactive = MAXACTIVE,
};
#endif

struct kretprobe execve_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(execve),
        .data_size  = sizeof(struct execve_data),
        .handler = execve_handler,
        .entry_handler = execve_entry_handler,
        .maxactive = MAXACTIVE,
};

#ifdef CONFIG_COMPAT
struct kretprobe compat_execve_kretprobe = {
    .kp.symbol_name = P_GET_COMPAT_SYSCALL_NAME(execve),
    .data_size  = sizeof(struct execve_data),
    .handler = execve_handler,
    .entry_handler = compat_execve_entry_handler,
    .maxactive = MAXACTIVE,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
struct kretprobe compat_execveat_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
    .data_size  = sizeof(struct execve_data),
    .handler = execve_handler,
    .entry_handler = compat_execveat_entry_handler,
    .maxactive = MAXACTIVE,
};
#endif
#endif

struct kretprobe security_inode_create_kretprobe = {
        .kp.symbol_name = "security_inode_create",
        .entry_handler = security_inode_create_entry_handler,
        .maxactive = MAXACTIVE,
};

struct kprobe ptrace_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(ptrace),
        .post_handler = ptrace_post_handler,
};

struct kretprobe udp_recvmsg_kretprobe = {
        .kp.symbol_name = "udp_recvmsg",
        .data_size  = sizeof(struct udp_recvmsg_data),
        .handler = udp_recvmsg_handler,
        .entry_handler = udp_recvmsg_entry_handler,
        .maxactive = MAXACTIVE,
};

#if IS_ENABLED(CONFIG_IPV6)
struct kretprobe udpv6_recvmsg_kretprobe = {
        .kp.symbol_name = "udpv6_recvmsg",
        .data_size  = sizeof(struct udp_recvmsg_data),
        .handler = udp_recvmsg_handler,
        .entry_handler = udpv6_recvmsg_entry_handler,
        .maxactive = MAXACTIVE,
};

struct kretprobe ip6_datagram_connect_kretprobe = {
        .kp.symbol_name = "ip6_datagram_connect",
        .data_size  = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = ip6_datagram_connect_entry_handler,
        .maxactive = MAXACTIVE,
};

struct kretprobe tcp_v6_connect_kretprobe = {
        .kp.symbol_name = "tcp_v6_connect",
        .data_size  = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = tcp_v6_connect_entry_handler,
        .maxactive = MAXACTIVE,
};
#endif

struct kretprobe ip4_datagram_connect_kretprobe = {
        .kp.symbol_name = "ip4_datagram_connect",
        .data_size  = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = ip4_datagram_connect_entry_handler,
        .maxactive = MAXACTIVE,
};

struct kretprobe tcp_v4_connect_kretprobe = {
        .kp.symbol_name = "tcp_v4_connect",
        .data_size  = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = tcp_v4_connect_entry_handler,
        .maxactive = MAXACTIVE,
};

struct kprobe load_module_kprobe = {
        .symbol_name = "load_module",
        .post_handler = load_module_post_handler,
};

struct kretprobe update_cred_kretprobe = {
        .kp.symbol_name = "commit_creds",
        .data_size  = sizeof(struct update_cred_data),
        .handler = update_cred_handler,
        .entry_handler = update_cred_entry_handler,
        .maxactive = MAXACTIVE,
};

int bind_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&bind_kretprobe);

    if (ret == 0)
        bind_kprobe_state = 0x1;

    return ret;
}

void unregister_kretprobe_bind(void) {
    unregister_kretprobe(&bind_kretprobe);
}

int execve_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&execve_kretprobe);
    if (ret == 0)
        execve_kprobe_state = 0x1;

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
int execveat_register_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&execveat_kretprobe);
    if (ret == 0)
        execveat_kretprobe_state = 0x1;

    return ret;
}
#endif

#ifdef CONFIG_COMPAT
int compat_execve_register_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&compat_execve_kretprobe);
    if (ret == 0)
        compat_execve_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_compat_execve(void)
{
    unregister_kretprobe(&compat_execve_kretprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
int compat_execveat_register_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&compat_execveat_kretprobe);
    if (ret == 0)
        compat_execveat_kretprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_compat_execveat(void)
{
    unregister_kretprobe(&compat_execveat_kretprobe);
}
#endif
#endif

void unregister_kprobe_execve(void) {
    unregister_kretprobe(&execve_kretprobe);
}

int create_file_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&security_inode_create_kretprobe);
    if (ret == 0)
        create_file_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_create_file(void) {
    unregister_kretprobe(&security_inode_create_kretprobe);
}

int ptrace_register_kprobe(void) {
    int ret;
    ret = register_kprobe(&ptrace_kprobe);

    if (ret == 0)
        ptrace_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_ptrace(void) {
    unregister_kprobe(&ptrace_kprobe);
}

int udp_recvmsg_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&udp_recvmsg_kretprobe);

    if (ret == 0)
        udp_recvmsg_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_udp_recvmsg(void) {
    unregister_kretprobe(&udp_recvmsg_kretprobe);
}

#if IS_ENABLED(CONFIG_IPV6)
int udpv6_recvmsg_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&udpv6_recvmsg_kretprobe);

    if (ret == 0)
        udpv6_recvmsg_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_udpv6_recvmsg(void) {
    unregister_kretprobe(&udpv6_recvmsg_kretprobe);
}

int ip6_datagram_connect_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&ip6_datagram_connect_kretprobe);

    if (ret == 0)
        ip6_datagram_connect_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_ip6_datagram_connect(void) {
    unregister_kretprobe(&ip6_datagram_connect_kretprobe);
}

int tcp_v6_connect_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&tcp_v6_connect_kretprobe);

    if (ret == 0)
        tcp_v6_connect_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_tcp_v6_connect(void) {
    unregister_kretprobe(&tcp_v6_connect_kretprobe);
}
#endif

int ip4_datagram_connect_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&ip4_datagram_connect_kretprobe);

    if (ret == 0)
        ip4_datagram_connect_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_ip4_datagram_connect(void) {
    unregister_kretprobe(&ip4_datagram_connect_kretprobe);
}

int tcp_v4_connect_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&tcp_v4_connect_kretprobe);

    if (ret == 0)
        tcp_v4_connect_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_tcp_v4_connect(void) {
    unregister_kretprobe(&tcp_v4_connect_kretprobe);
}

int load_module_register_kprobe(void) {
    int ret;
    ret = register_kprobe(&load_module_kprobe);

    if (ret == 0)
        load_module_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_load_module(void) {
    unregister_kprobe(&load_module_kprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
void unregister_kprobe_execveat(void)
{
    unregister_kretprobe(&execveat_kretprobe);
}
#endif

int update_cred_register_kprobe(void) {
    int ret;
    ret = register_kretprobe(&update_cred_kretprobe);
    if (ret == 0)
        update_cred_kprobe_state = 0x1;

    return ret;
}

void unregister_kprobe_update_cred(void) {
    unregister_kretprobe(&update_cred_kretprobe);
}

void uninstall_kprobe(void) {
    if (bind_kprobe_state == 0x1)
        unregister_kretprobe_bind();

    if (execve_kprobe_state == 0x1)
        unregister_kprobe_execve();

    if (create_file_kprobe_state == 0x1)
        unregister_kprobe_create_file();

    if (ptrace_kprobe_state == 0x1)
        unregister_kprobe_ptrace();

    if (udp_recvmsg_kprobe_state == 0x1)
        unregister_kprobe_udp_recvmsg();

    if (udpv6_recvmsg_kprobe_state == 0x1)
        unregister_kprobe_udpv6_recvmsg();

    if (load_module_kprobe_state == 0x1)
        unregister_kprobe_load_module();

    if (update_cred_kprobe_state == 0x1)
        unregister_kprobe_update_cred();

    if (tcp_v4_connect_kprobe_state == 0x1)
        unregister_kprobe_tcp_v4_connect();

    if (tcp_v6_connect_kprobe_state == 0x1)
        unregister_kprobe_tcp_v6_connect();

    if (ip4_datagram_connect_kprobe_state == 0x1)
        unregister_kprobe_ip4_datagram_connect();

    if (ip6_datagram_connect_kprobe_state == 0x1)
        unregister_kprobe_ip6_datagram_connect();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (execveat_kretprobe_state == 0x1)
        unregister_kprobe_execveat();
#endif

#ifdef CONFIG_COMPAT
    unregister_kprobe_compat_execve();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    unregister_kprobe_compat_execveat();
#endif
#endif

}

int __init

smith_init(void) {
    int ret;
    checkCPUendianRes = checkCPUendian();

    ret = init_share_mem();

    if (ret != 0)
        return ret;
    else
        printk(KERN_INFO
    "[SMITH] init_share_mem success \n");

    ret = init_filter();
    if (ret != 0)
        return ret;
    else
        printk(KERN_INFO
    "[SMITH] filter init success \n");

    if (CONNECT_HOOK == 1) {
        ret = tcp_v4_connect_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] connect register_kprobe failed, returned %d\n", ret);
        }

        ret = ip4_datagram_connect_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] ip4_datagram_connect register_kprobe failed, returned %d\n", ret);
        }

#if IS_ENABLED(CONFIG_IPV6)
        ret = tcp_v6_connect_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] tcp_v6_connect register_kprobe failed, returned %d\n", ret);
        }

        ret = ip6_datagram_connect_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] ip6_datagram_connect register_kprobe failed, returned %d\n", ret);
        }
#endif
    }

    if (BIND_HOOK == 1) {
        ret = bind_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] bind register_kprobe failed, returned %d\n", ret);
        }
    }

    if (EXECVE_HOOK == 1) {
        ret = execve_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] execve register_kprobe failed, returned %d\n", ret);
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        ret = execveat_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO "[SMITH] execveat register_kprobe failed, returned %d\n", ret);
        }
#endif

#ifdef CONFIG_COMPAT
        ret = compat_execve_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO "[SMITH] compat_sys_execve register_kprobe failed, returned %d\n", ret);
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        ret = compat_execveat_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO "[SMITH] compat_sys_execveat register_kprobe failed, returned %d\n", ret);
        }
#endif

#endif
    }

    if (CREATE_FILE_HOOK == 1) {
        ret = create_file_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] create_file register_kprobe failed, returned %d\n", ret);
        }
    }

    if (PTRACE_HOOK == 1) {
        ret = ptrace_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] ptrace register_kprobe failed, returned %d\n", ret);
        }
    }

    if (DNS_HOOK == 1) {
        ret = udp_recvmsg_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] udp_recvmsg register_kprobe failed, returned %d\n", ret);
        }

#if IS_ENABLED(CONFIG_IPV6)
        ret = udpv6_recvmsg_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] udpv6_recvmsg register_kprobe failed, returned %d\n", ret);
        }
#endif
    }

    if (LOAD_MODULE_HOOK == 1) {
        ret = load_module_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] load_module register_kprobe failed, returned %d\n", ret);
        }
    }

    if (UPDATE_CRED_HOOK == 1) {
        ret = update_cred_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO
            "[SMITH] update_cred register_kprobe failed, returned %d\n", ret);
        }
    }

#if (EXIT_PROTECT == 1)
    exit_protect_action();
#endif

#if (ROOTKIT_CHECK == 1)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    anti_rootkit_init();
#endif
#endif

    printk(KERN_INFO
    "[SMITH] register_kprobe success: connect_hook: %d,load_module_hook:"
    " %d,execve_hook: %d,bind_hook: %d,create_file_hook: %d,ptrace_hook: %d, update_cred_hook:"
    " %d, DNS_HOOK: %d,EXIT_PROTECT: %d,ROOTKIT_CHECK: %d\n",
            CONNECT_HOOK, LOAD_MODULE_HOOK, EXECVE_HOOK, BIND_HOOK, CREATE_FILE_HOOK,
            PTRACE_HOOK, UPDATE_CRED_HOOK, DNS_HOOK, EXIT_PROTECT, ROOTKIT_CHECK);

    return 0;
}

void __exit

smith_exit(void) {
#if (ROOTKIT_CHECK == 1)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    anti_root_kit_exit();
#endif
#endif

    uninstall_kprobe();
    uninstall_share_mem();
    uninstall_filter();
    printk(KERN_INFO
    "[SMITH] uninstall_kprobe success\n");
}

module_init(smith_init)
module_exit(smith_exit)

MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.2.5");
MODULE_AUTHOR("E_Bwill <cy_sniper@yeah.net>");
MODULE_DESCRIPTION("get execve,connect,bind,ptrace,load_module,dns_query,create_file,cred_change,"
"and proc_file_hook,syscall_hook,lkm_hidden,interrupts_hook info");