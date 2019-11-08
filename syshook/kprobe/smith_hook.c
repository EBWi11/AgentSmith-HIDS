/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2019
* File:		smith_hook.c
* Description:	hook sys_execve,sys_connect,sys_ptrace,load_module,fsnotify,sys_recvfrom

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
#include "smith_hook.h"

#define EXIT_PROTECT 0

#define CONNECT_HOOK 1
#define EXECVE_HOOK 1
#define FSNOTIFY_HOOK 0
#define PTRACE_HOOK 1
#define RECVFROM_HOOK 1
#define LOAD_MODULE_HOOK 1

int share_mem_flag = -1;
int checkCPUendianRes = 0;
char connect_kprobe_state = 0x0;
char execve_kprobe_state = 0x0;
char fsnotify_kprobe_state = 0x0;
char ptrace_kprobe_state = 0x0;
char recvfrom_kprobe_state = 0x0;
char load_module_kprobe_state = 0x0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)

struct filename *(*tmp_getname)(const char __user *filename);
void (*tmp_putname)(struct filename *name);

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

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
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

static int count(struct user_arg_ptr argv, int max)
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
            cond_resched();
        }
    }
    return i;
}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
static int count(char __user * __user * argv, int max)
{
	int i = 0;

	if (argv != NULL) {
		for (;;) {
			char __user * p;

			if (get_user(p, argv))
				return -EFAULT;
			if (!p)
				break;
			argv++;
			if (i++ >= max)
				return -E2BIG;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

static char *dentry_path_raw(void)
{
    char *cwd;
    char *pname_buf = NULL;
    struct path pwd, root;
    pwd = current->fs->pwd;
    path_get(&pwd);
    root = current->fs->root;
    path_get(&root);
    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    cwd = d_path(&pwd, pname_buf, PATH_MAX);
    kfree(pname_buf);
    return cwd;
}
#endif

static char *str_replace(char *orig, char *rep, char *with)
{
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

    if (!result)
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

struct connect_data {
    int fd;
    struct sockaddr *dirp;
};

struct recvfrom_data {
    int fd;
};

struct fsnotify_data {
    int fd;
};

struct load_module_data {
    int fd;
};

#if EXIT_PROTECT == 1
static void exit_protect_action(void)
{
    __module_get(THIS_MODULE);
}
#endif

static int checkCPUendian(void)
{
    union {
        unsigned long int i;
        unsigned char s[4];
    } c;
    c.i = 0x12345678;
    return (0x12 == c.s[0]);
}

unsigned short int Ntohs(unsigned short int n)
{
    return checkCPUendianRes ? n : BigLittleSwap16(n);
}

static unsigned int get_sessionid(void)
{
    unsigned int sessionid = 0;
#ifdef CONFIG_AUDITSYSCALL
    sessionid = current -> sessionid;
#endif
    return sessionid;
}

static int connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct connect_data *data;
    data = (struct connect_data *)ri->data;
    data->fd = regs->di;
    data->dirp = (struct sockaddr *)regs->si;
    return 0;
}

static int connect_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int err;
    int fd;
    int flag = 0;
    int copy_res;
    int retval;
    int sa_family;
    int result_str_len;
    int pid_check_res = -1;
    int file_check_res = -1;
    unsigned int sessionid;
    struct socket *socket;
    struct sock *sk;
    struct sockaddr tmp_dirp;
    struct connect_data *data;
    struct inet_sock *inet;
    char dip[64];
    char sip[64];
    char dport[16] = "-1";
    char sport[16] = "-1";
    char *final_path = NULL;
    char *result_str;

	if (share_mem_flag != -1) {
	    sessionid = get_sessionid();
	    retval = regs_return_value(regs);

        data = (struct connect_data *)ri->data;
        fd = data->fd;

        if(!fd)
            goto out;

        socket = sockfd_lookup(fd, &err);

        copy_res = copy_from_user(&tmp_dirp, data->dirp, 16);

        if(socket) {
            if(unlikely(!copy_res)) {
                sockfd_put(socket);
                goto out;
            }

            switch (tmp_dirp.sa_family) {
                case AF_INET:
                    sk = socket->sk;
                    inet = (struct inet_sock*)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
                    if (inet->inet_dport) {
                        snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_daddr));
                        snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->inet_saddr));
                        snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                        snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                        flag = 1;
                    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
                    if (inet->dport) {
                        snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(inet->daddr));
                        snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(inet->saddr));
                        snprintf(sport, 16, "%d", Ntohs(inet->sport));
                        snprintf(dport, 16, "%d", Ntohs(inet->dport));
                        flag = 1;
                    }
#endif
                    sa_family = 4;
                    break;
#if IS_ENABLED(CONFIG_IPV6)
                case AF_INET6:
                    sk = socket->sk;
                    inet = (struct inet_sock*)sk;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
                    if (inet->inet_dport) {
                        snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_daddr));
                        snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_rcv_saddr));
                        snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                        snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                        flag = 1;
                    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
                    if (inet->dport) {
                        snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(inet->pinet6->daddr));
                        snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(inet->pinet6->saddr));
                        snprintf(sport, 16, "%d", Ntohs(inet->sport));
                        snprintf(dport, 16, "%d", Ntohs(inet->dport));
                        flag = 1;
                    }
#endif
                    sa_family = 6;
                    break;
#endif
                default:
                    break;
            }
            sockfd_put(socket);
        }

        if(likely(flag == 1)) {
            if (current->active_mm) {
                if (current->mm->exe_file) {
                    char connect_pathname[PATH_MAX];
                    final_path = d_path(&current->mm->exe_file->f_path, connect_pathname, PATH_MAX);
                }
            }

            if (unlikely(final_path == NULL)) {
                final_path = "-1";
            }

            result_str_len = strlen(current->comm) +
                             strlen(current->nsproxy->uts_ns->name.nodename) +
                             strlen(current->comm) + strlen(final_path) + 128;

            result_str = kzalloc(result_str_len, GFP_ATOMIC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
            snprintf(result_str, result_str_len,
                    "%d%s%s%s%d%s%d%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%u",
                    current->real_cred->uid.val, "\n", CONNECT_TYPE, "\n", sa_family,
                    "\n", fd, "\n", dport, "\n", dip, "\n", final_path, "\n",
                    current->pid, "\n", current->real_parent->pid, "\n",
                    pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                    current->comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n",
                    sip, "\n", sport, "\n", retval, "\n", pid_check_res, "\n",
                    file_check_res, "\n", sessionid);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
            snprintf(result_str, result_str_len,
                    "%d%s%s%s%d%s%d%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%u",
                    current->real_cred->uid, "\n", CONNECT_TYPE, "\n", sa_family,
                    "\n", fd, "\n", dport, "\n", dip, "\n", final_path, "\n",
                    current->pid, "\n", current->real_parent->pid, "\n",
                    pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                    current->comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n",
                    sip, "\n", sport, "\n", retval, "\n", pid_check_res, "\n",
                    file_check_res, "\n", sessionid);
#endif
            send_msg_to_user(result_str, 1);
        }
    }

    return 0;

out:
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void execve_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, flag = 0;
    int result_str_len;
    int pid_check_res = -1;
    int file_check_res = -1;
    unsigned int sessionid;
    char *result_str = NULL;
    char *abs_path = NULL;
    char *pname = NULL;
    char *tmp_stdin = NULL;
    char *tmp_stdout = NULL;
    char *argv_res = NULL;
    char *argv_res_tmp = NULL;
    struct filename *path;
    struct fdtable *files;
    const char __user *native;

	if (share_mem_flag != -1) {
	    sessionid = get_sessionid();
	    struct user_arg_ptr argv_ptr = {.ptr.native = regs->si};
	    char tmp_stdin_fd[PATH_MAX];
        char tmp_stdout_fd[PATH_MAX];
        char pname_buf[PATH_MAX];

        path = tmp_getname((char *) regs->di);
        if (likely(!IS_ERR(path)))
            abs_path = (char *)path->name;
        else
            abs_path = "-1";

	    files = files_fdtable(current->files);

        if(likely(files->fd[0] != NULL))
            tmp_stdin = d_path(&(files->fd[0]->f_path), tmp_stdin_fd, PATH_MAX);
        else
            tmp_stdin = "-1";

        if(likely(files->fd[1] != NULL))
            tmp_stdout = d_path(&(files->fd[1]->f_path), tmp_stdout_fd, PATH_MAX);
        else
            tmp_stdout = "-1";

        pname = dentry_path_raw(current->fs->pwd.dentry, pname_buf, PATH_MAX - 1);

        argv_len = count(argv_ptr, MAX_ARG_STRINGS);
        if(likely(argv_len > 0))
            argv_res = kzalloc(128 * argv_len + 1, GFP_ATOMIC);

        if (likely(argv_len > 0)) {
            for (i = 0; i < argv_len; i++) {
                native = get_user_arg_ptr(argv_ptr, i);
                if (unlikely(IS_ERR(native))) {
                    flag = -1;
                    break;
                }

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if (!len) {
                    flag = -2;
                    break;
                }

                if (offset + len > argv_res_len + 128 * argv_len) {
                    flag = -3;
                    break;
                }

                if (copy_from_user(argv_res + offset, native, len)) {
                    flag = -4;
                    break;
                }

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }

        if (argv_len > 0 && flag == 0)
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        result_str_len = strlen(argv_res_tmp) + strlen(pname) + strlen(abs_path) +
                         strlen(current->nsproxy->uts_ns->name.nodename) + 1024;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);
        snprintf(result_str, result_str_len,
                 "%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%d%s%d%s%u",
                 current->real_cred->uid.val, "\n", EXECVE_TYPE, "\n", pname, "\n",
                 abs_path, "\n", argv_res_tmp, "\n", current->pid, "\n",
                 current->real_parent->pid, "\n", pid_vnr(task_pgrp(current)),
                 "\n", current->tgid, "\n", current->comm, "\n",
                 current->nsproxy->uts_ns->name.nodename,"\n",tmp_stdin,"\n",tmp_stdout,
                 "\n",pid_check_res, "\n",file_check_res, "\n", sessionid);

        send_msg_to_user(result_str, 1);

        if(likely(argv_len > 0))
            kfree(argv_res);

        if (strcmp(abs_path, "-1"))
            tmp_putname(path);
	}
}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
static void execve_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, flag = 0;
    int result_str_len;
    int pid_check_res = -1;
    int file_check_res = -1;
    unsigned int sessionid;
    char *result_str = NULL;
    char *pname = NULL;
    char *tmp_stdin = NULL;
    char *tmp_stdout = NULL;
    char *argv_res = NULL;
    char *argv_res_tmp = NULL;
    struct fdtable *files;
    const char __user *native;

	if (share_mem_flag != -1) {
	    sessionid = get_sessionid();
	    char **argv = (char **) regs->si;
	    char tmp_stdin_fd[PATH_MAX];
        char tmp_stdout_fd[PATH_MAX];

        char filename[2048];
        int copy_res = copy_from_user(filename, (char *) regs->di, 2048);
        if(copy_res)
            copy_res = "";

	    files = files_fdtable(current->files);

        if(likely(files->fd[0] != NULL))
            tmp_stdin = d_path(&(files->fd[0]->f_path), tmp_stdin_fd, PATH_MAX);
        else
            tmp_stdin = "-1";

        if(likely(files->fd[1] != NULL))
            tmp_stdout = d_path(&(files->fd[1]->f_path), tmp_stdout_fd, PATH_MAX);
        else
            tmp_stdout = "-1";

        pname = dentry_path_raw();

        argv_len = count(argv, MAX_ARG_STRINGS);
        if(likely(argv_len > 0))
            argv_res = kzalloc(128 * argv_len + 1, GFP_ATOMIC);

        if (likely(argv_len > 0)) {
            for(i = 0; i < argv_len; i ++) {
                if(i == 0) {
                    continue;
                }
                    
                if(get_user(native, argv + i)) {
                    flag = -1;
                    break;
                }

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len) {
                    flag = -2;
                    break;
                }

                if(offset + len > argv_res_len + 128 * argv_len) {
                    flag = -3;
                    break;
                }

                if (copy_from_user(argv_res + offset, native, len)) {
                    flag = -4;
                    break;
                }

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }

        if (argv_len > 0 && flag == 0)
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        result_str_len = strlen(argv_res_tmp) + strlen(pname) +
                         strlen(filename) +
                         strlen(current->nsproxy->uts_ns->name.nodename) + 128;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);
        snprintf(result_str, result_str_len,
                 "%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%d%s%d%s%u",
                 current->real_cred->uid, "\n", EXECVE_TYPE, "\n", pname, "\n",
                 filename, "\n", argv_res_tmp, "\n", current->pid, "\n",
                 current->real_parent->pid, "\n", pid_vnr(task_pgrp(current)),
                 "\n", current->tgid, "\n", current->comm, "\n",
                 current->nsproxy->uts_ns->name.nodename,"\n",tmp_stdin,"\n",tmp_stdout,
                 "\n",pid_check_res, "\n",file_check_res, "\n", sessionid);

        send_msg_to_user(result_str, 1);

        if(likely(argv_len > 0))
            kfree(argv_res);
	}
}
#endif

static void fsnotify_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("fsnotify---------------------------------\n", 0);
	}
}

static void ptrace_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int result_str_len;
    long request;
    long pid;
    unsigned long addr;
    unsigned long data;
    char *final_path = NULL;
    char *result_str = NULL;
    unsigned int sessionid;

	if (share_mem_flag != -1) {
	    request = (long) regs->di;
	    pid = (long) regs->si;
	    addr = (unsigned long) regs->dx;
	    data = (unsigned long) regs->r10;
	    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
	        sessionid = get_sessionid();
	        if (current->active_mm) {
                if (current->mm->exe_file) {
                    char ptrace_pathname[PATH_MAX];
                    final_path = d_path(&current->mm->exe_file->f_path, ptrace_pathname, PATH_MAX);
                }

                if (final_path == NULL)
                    final_path = "-1";

                result_str_len = strlen(current->comm) +
                                 strlen(current->nsproxy->uts_ns->name.nodename) +
                                 strlen(current->comm) + strlen(final_path) + 256;

                result_str = kzalloc(result_str_len, GFP_ATOMIC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
                snprintf(result_str, result_str_len,
                         "%d%s%s%s%d%s%d%s%p%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                         current->real_cred->uid.val, "\n", PTRACE_TYPE, "\n", request,
                         "\n", pid, "\n", addr, "\n", &data, "\n", final_path, "\n",
                         current->pid, "\n", current->real_parent->pid, "\n",
                         pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                         current->comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);
                send_msg_to_user(result_str, 1);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
                snprintf(result_str, result_str_len,
                         "%d%s%s%s%d%s%d%s%p%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                         current->real_cred->uid, "\n", PTRACE_TYPE, "\n", request,
                         "\n", pid, "\n", addr, "\n", &data, "\n", final_path, "\n",
                         current->pid, "\n", current->real_parent->pid, "\n",
                         pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                         current->comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);
                send_msg_to_user(result_str, 1);
#endif
            }
	    }
	}
}

static void recvfrom_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("recvfrom---------------------------------\n", 0);
	}
}

static void load_module_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int i = 0;
    int result_str_len;
    unsigned int sessionid;
    char *cwd = NULL;
    char *result_str = NULL;
    struct path files_path;
    struct files_struct *current_files;
    struct fdtable *files_table;

	if (share_mem_flag != -1) {
        sessionid = get_sessionid();
        current_files = current->files;
        files_table = files_fdtable(current_files);
        char init_module_buf[PATH_MAX];

        while (files_table->fd[i] != NULL)
            i++;

        files_path = files_table->fd[i - 1]->f_path;
        cwd = d_path(&files_path, init_module_buf, PATH_MAX);
        result_str_len = strlen(cwd) + 192;
        result_str = kzalloc(result_str_len, GFP_ATOMIC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        snprintf(result_str, result_str_len, "%d%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                 current->real_cred->uid.val, "\n", LOAD_MODULE_TYPE, "\n", cwd,
                 "\n", current->pid, "\n", current->real_parent->pid, "\n",
                 pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                 current->comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);
        send_msg_to_user(result_str, 1);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
        snprintf(result_str, result_str_len, "%d%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                 current->real_cred->uid, "\n", LOAD_MODULE_TYPE, "\n", cwd,
                 "\n", current->pid, "\n", current->real_parent->pid, "\n",
                 pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                 current->comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);
        send_msg_to_user(result_str, 1);
#endif
	}
}

static struct kretprobe connect_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(connect),
    .data_size  = sizeof(struct connect_data),
	.handler = connect_handler,
    .entry_handler = connect_entry_handler,
    .maxactive = 40,
};

static struct kprobe execve_kprobe = {
    .symbol_name = P_GET_SYSCALL_NAME(execve),
	.post_handler = execve_post_handler,
};

static struct kprobe fsnotify_kprobe = {
    .symbol_name = "fsnotify",
	.post_handler = fsnotify_post_handler,
};

static struct kprobe ptrace_kprobe = {
    .symbol_name = P_GET_SYSCALL_NAME(ptrace),
	.post_handler = ptrace_post_handler,
};

static struct kprobe recvfrom_kprobe = {
    .symbol_name = P_GET_SYSCALL_NAME(recvfrom),
	.post_handler = recvfrom_post_handler,
};

static struct kprobe load_module_kprobe = {
    .symbol_name = "load_module",
	.post_handler = load_module_post_handler,
};

static int connect_register_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&connect_kretprobe);

	if (ret == 0)
        connect_kprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_connect(void)
{
	unregister_kretprobe(&connect_kretprobe);
}

static int execve_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&execve_kprobe);

	if (ret == 0)
        execve_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_execve(void)
{
	unregister_kprobe(&execve_kprobe);
}

static int fsnotify_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&fsnotify_kprobe);

	if (ret == 0)
        fsnotify_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_fsnotify(void)
{
	unregister_kprobe(&fsnotify_kprobe);
}

static int ptrace_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&ptrace_kprobe);

	if (ret == 0)
        ptrace_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_ptrace(void)
{
	unregister_kprobe(&ptrace_kprobe);
}

static int recvfrom_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&recvfrom_kprobe);

	if (ret == 0)
        recvfrom_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_recvfrom(void)
{
	unregister_kprobe(&recvfrom_kprobe);
}

static int load_module_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&load_module_kprobe);

	if (ret == 0)
        load_module_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_load_module(void)
{
	unregister_kprobe(&load_module_kprobe);
}

static void uninstall_kprobe(void)
{
    if (connect_kprobe_state == 0x1)
	    unregister_kretprobe_connect();

    if (execve_kprobe_state == 0x1)
	    unregister_kprobe_execve();

    if (fsnotify_kprobe_state == 0x1)
	    unregister_kprobe_fsnotify();

    if (ptrace_kprobe_state == 0x1)
	    unregister_kprobe_ptrace();

    if (recvfrom_kprobe_state == 0x1)
	    unregister_kprobe_recvfrom();

    if (load_module_kprobe_state == 0x1)
	    unregister_kprobe_load_module();
}

static int __init smith_init(void)
{
	int ret;
	checkCPUendianRes = checkCPUendian();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    tmp_getname = (void *)kallsyms_lookup_name("getname");

    if(!tmp_getname) {
            printk(KERN_INFO "[SMITH] UNKNOW_SYMBOL: getname()\n");
            return -1;
    }
    tmp_putname = (void *)kallsyms_lookup_name("putname");

    if(!tmp_putname) {
            printk(KERN_INFO "[SMITH] UNKNOW_SYMBOL: putname()\n");
            return -1;
    }
#endif

    ret = init_share_mem();

    if (ret != 0)
        return ret;
    else
        printk(KERN_INFO "[SMITH] init_share_mem success \n");

    if (CONNECT_HOOK == 1) {
	    ret = connect_register_kprobe();
	    if (ret < 0) {
	    	uninstall_share_mem();
		    printk(KERN_INFO "[SMITH] connect register_kprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (EXECVE_HOOK == 1) {
	ret = execve_register_kprobe();
	    if (ret < 0) {
		    uninstall_kprobe();
		    uninstall_share_mem();
		    printk(KERN_INFO "[SMITH] execve register_kprobe failed, returned %d\n", ret);
	    	return -1;
	    }
	}

    if (FSNOTIFY_HOOK == 1) {
	ret = fsnotify_register_kprobe();
	    if (ret < 0) {
		    uninstall_kprobe();
		    uninstall_share_mem();
		    printk(KERN_INFO "[SMITH] fsnotify register_kprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (PTRACE_HOOK == 1) {
	ret = ptrace_register_kprobe();
	    if (ret < 0) {
		    uninstall_kprobe();
		    uninstall_share_mem();
		    printk(KERN_INFO "[SMITH] ptrace register_kprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (RECVFROM_HOOK == 1) {
	ret = recvfrom_register_kprobe();
	    if (ret < 0) {
		    uninstall_kprobe();
		    printk(KERN_INFO "[SMITH] recvfrom register_kprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (LOAD_MODULE_HOOK == 1) {
	ret = load_module_register_kprobe();
	    if (ret < 0) {
		    uninstall_kprobe();
		    printk(KERN_INFO "[SMITH] load_module register_kprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

#if (EXIT_PROTECT == 1)
    exit_protect_action()
#endif

	printk(KERN_INFO "[SMITH] register_kprobe success: connect_hook: %d,load_module_hook: %d,execve_hook: %d,fsnotify_hook: %d,ptrace_hook: %d,recvfrom_hook: %d\n",
	       CONNECT_HOOK, LOAD_MODULE_HOOK, EXECVE_HOOK, FSNOTIFY_HOOK, PTRACE_HOOK, RECVFROM_HOOK);

	return 0;
}

static void __exit smith_exit(void)
{
	uninstall_kprobe();
	uninstall_share_mem();
	printk(KERN_INFO "[SMITH] uninstall_kprobe success\n");
}

module_init(smith_init)
module_exit(smith_exit)

MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.0.1");
MODULE_AUTHOR("E_Bwill <cy_sniper@yeah.net>");
MODULE_DESCRIPTION("hook sys_execve,sys_connect,sys_ptrace,load_module,fsnotify,sys_recvfrom");