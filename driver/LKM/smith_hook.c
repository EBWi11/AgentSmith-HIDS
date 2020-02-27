/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2019
* File:		smith_hook.c
* Description:	get execve,connect,ptrace,load_module,dns_query,create_file,cred_change,proc_file_hook,syscall_hook,lkm_hidden,interrupts_hook info

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
#include "struct_wrap.h"

#define EXIT_PROTECT 0
#define ROOTKIT_CHECK 1

#define CONNECT_HOOK 1
#define EXECVE_HOOK 1
#define CREATE_FILE_HOOK 1
#define PTRACE_HOOK 1
#define DNS_HOOK 1
#define MPROTECT_HOOK 0
#define LOAD_MODULE_HOOK 1
#define UPDATE_CRED_HOOK 1

int share_mem_flag = -1;
int checkCPUendianRes = 0;

char connect_kprobe_state = 0x0;
char execve_kprobe_state = 0x0;
char compat_execve_kprobe_state = 0x0;
char create_file_kprobe_state = 0x0;
char ptrace_kprobe_state = 0x0;
char recvfrom_kprobe_state = 0x0;
char load_module_kprobe_state = 0x0;
char update_cred_kprobe_state = 0x0;
char mprotect_kprobe_state = 0x0;

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
            cond_resched();
        }
    }
    return i;
}
#else
char *_dentry_path_raw(void)
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

int count(char **argv, int max)
{
	int i = 0;

	if (argv != NULL) {
		for (;;) {
			char * p;

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
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
char *getfullpath(struct inode *inod,char *buffer,int len)
{
	struct hlist_node* plist = NULL;
	struct dentry* tmp = NULL;
	struct dentry* dent = NULL;
	char* name = NULL;
	struct inode* pinode = inod;

	buffer[len - 1] = '\0';
	if(pinode == NULL)
		return NULL;

	hlist_for_each(plist, &pinode->i_dentry) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 1)
		tmp = hlist_entry(plist, struct dentry, d_u.d_alias);
#else
		tmp = hlist_entry(plist, struct dentry, d_alias);
#endif
		if(tmp->d_inode == pinode) {
			dent = tmp;
			break;
		}
	}

	if(dent == NULL) {
		return NULL;
	}

	name = dentry_path_raw(dent, buffer, len);
	return name;
}
#else
int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
	return prepend(buffer, buflen, name->name, name->len);
}

char *__dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *end = buf + buflen;
	char *retval;

	prepend(&end, &buflen, "\0", 1);
	if (buflen < 1)
		goto Elong;
	retval = end-1;
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

char *getfullpath(struct inode *inod, char* buffer, int len)
{
	struct list_head* plist = NULL;
	struct dentry* tmp = NULL;
	struct dentry* dent = NULL;
	char* name = NULL;
	struct inode* pinode = inod;

	buffer[PATH_MAX - 1] = '\0';
	if(pinode == NULL)
		return NULL;

	list_for_each(plist,&pinode->i_dentry) {
		tmp = list_entry(plist, struct dentry, d_alias);
		if(tmp->d_inode == pinode) {
			dent = tmp;
			break;
		}
	}

	if(dent == NULL)
		return NULL;

    spin_lock(&inod->i_lock);
	name = __dentry_path(dent, buffer, len);
	spin_unlock(&inod->i_lock);

	return name;
}
#endif

char *get_exe_file(struct task_struct *task, char *buffer, int size)
{
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

char *str_replace(char *orig, char *rep, char *with)
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

char *get_pid_tree(void)
{
    int data_len;
    char *tmp_data;
    char *res;
    char *comm;
    char pid[sizeof(size_t)];
    struct task_struct *task;

    task = current;

    if(strlen(task->comm) > 0)
        comm = str_replace(current->comm, "\n", " ");
    else
        comm = "";

    snprintf(pid,sizeof(size_t),"%d",task->pid);
    tmp_data = kzalloc(4096, GFP_ATOMIC);
    strcat(tmp_data, pid);
    strcat(tmp_data,"(");
    strcat(tmp_data,comm);
    strcat(tmp_data,")");

    while(task->pid != 1){
        task = task->parent;
        data_len = strlen(task->comm) + sizeof(size_t) + 8;

        if(data_len > sizeof(size_t) + 8)
            comm = str_replace(task->comm, "\n", " ");
        else
            comm = "";

        res = kzalloc(data_len + strlen(tmp_data), GFP_ATOMIC);

        snprintf(pid,sizeof(size_t),"%d",task->pid);
        strcat(res,pid);
        strcat(res,"(");
        strcat(res,comm);
        strcat(res,")->");
        strcat(res,tmp_data);
        strcpy(tmp_data, res);
        kfree(res);
    }

    return tmp_data;
}

struct connect_data {
    int fd;
    struct sockaddr *dirp;
};

struct recvfrom_data {
    int fd;
    struct sockaddr *dirp;
    void *ubuf;
    size_t size;
    int addr_len;
};

struct create_file_data {
    int fd;
};


#if EXIT_PROTECT == 1
void exit_protect_action(void)
{
    __module_get(THIS_MODULE);
}
#endif

int checkCPUendian(void)
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

unsigned int get_sessionid(void)
{
    unsigned int sessionid = 0;
#ifdef CONFIG_AUDITSYSCALL
    sessionid = current -> sessionid;
#endif
    return sessionid;
}

int connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct connect_data *data;
    if (share_mem_flag != -1) {
        data = (struct connect_data *)ri->data;
        data->fd = p_get_arg1(regs);
        data->dirp = (struct sockaddr *)p_get_arg2(regs);
    }
    return 0;
}

int connect_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int err;
    int fd;
    int flag = 0;
    int copy_res;
    int retval;
    int sa_family;
    int result_str_len;

	if (share_mem_flag != -1) {
	    unsigned int sessionid;
        char dip[64] = "-1";
        char sip[64] = "-1";
        char dport[16] = "-1";
        char sport[16] = "-1";
        char *abs_path = NULL;
        char *result_str;
        char *comm = NULL;
        char *buffer = NULL;
	    struct socket *socket;
        struct sock *sk;
        struct sockaddr tmp_dirp;
        struct connect_data *data;
        struct inet_sock *inet;

	    sessionid = get_sessionid();
	    retval = regs_return_value(regs);

        data = (struct connect_data *)ri->data;
        fd = data->fd;

        if(unlikely(!fd))
            goto out;

        socket = sockfd_lookup(fd, &err);
        if(likely(socket)) {
            copy_res = copy_from_user(&tmp_dirp, data->dirp, 16);

            if(unlikely(copy_res)) {
                sockfd_put(socket);
                goto out;
            }

            switch (tmp_dirp.sa_family) {
                case AF_INET:
                    sk = socket->sk;
                    inet = (struct inet_sock*)sk;
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
                    sa_family = AF_INET;
                    break;
#if IS_ENABLED(CONFIG_IPV6)
                case AF_INET6:
                    sk = socket->sk;
                    inet = (struct inet_sock*)sk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
                    if (likely(inet->inet_dport)) {
                        snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_daddr));
                        snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_rcv_saddr));
                        snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                        snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                        flag = 1;
                    }
#else
                    if (likely(inet->dport)) {
                        snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(inet->pinet6->daddr));
                        snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(inet->pinet6->saddr));
                        snprintf(sport, 16, "%d", Ntohs(inet->sport));
                        snprintf(dport, 16, "%d", Ntohs(inet->dport));
                        flag = 1;
                    }
#endif
                    sa_family = AF_INET6;
                    break;
#endif
                default:
                    break;
            }
            sockfd_put(socket);
        }

        if(flag == 1) {
            buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
            abs_path = get_exe_file(current, buffer, PATH_MAX);

            if(strlen(current->comm) > 0)
                comm = str_replace(current->comm, "\n", " ");
            else
                comm = "";

            result_str_len = strlen(current->nsproxy->uts_ns->name.nodename) +
                             strlen(comm) + strlen(abs_path) + 172;

            result_str = kzalloc(result_str_len, GFP_ATOMIC);

            snprintf(result_str, result_str_len,
                    "%d%s%s%s%d%s%d%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%d%s%u",
                    get_current_uid(), "\n", CONNECT_TYPE, "\n", sa_family,
                    "\n", fd, "\n", dport, "\n", dip, "\n", abs_path, "\n",
                    current->pid, "\n", current->real_parent->pid, "\n",
                    pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                    comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n",
                    sip, "\n", sport, "\n", retval, "\n", sessionid);

            send_msg_to_user(result_str, 1);
            kfree(buffer);
        }
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
};

#ifdef CONFIG_COMPAT
int compat_execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, error = 0;
    int env_len = 0;
    char *exe_file_buf = "-2";
    char *argv_res = NULL;
    char *abs_path = NULL;
    char *argv_res_tmp = NULL;
    const char __user *native;
    if (share_mem_flag != -1) {
        char *ssh_connection = NULL;
        char *ld_preload = NULL;
        struct execve_data *data;
        struct path exe_file;

        struct user_arg_ptr argv_ptr = {
            .is_compat = true,
        	.ptr.compat = (const compat_uptr_t __user *)p_get_arg2(regs),
        };

        struct user_arg_ptr env_ptr = {
            .is_compat = true,
        	.ptr.compat = (const compat_uptr_t __user *)p_get_arg3(regs),
        };

        data = (struct execve_data *)ri->data;

        env_len = count(env_ptr, MAX_ARG_STRINGS);
        argv_res_len = 128 * (argv_len + 2);
        argv_len = count(argv_ptr, MAX_ARG_STRINGS);

        if(likely(argv_len > 0)) {
            argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
            for (i = 0; i < argv_len; i++) {
                native = get_user_arg_ptr(argv_ptr, i);
                if (unlikely(IS_ERR(native)))
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
        }
        
        ssh_connection = kzalloc(255, GFP_ATOMIC);
        ld_preload = kzalloc(255, GFP_ATOMIC);

        if(likely(env_len > 0)) {
            char buf[256];
            for (i = 0; i < env_len; i++) {
                native = get_user_arg_ptr(env_ptr, i);
                if (unlikely(IS_ERR(native)))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;
                else if(len > 14) {
                    memset(buf, 0, 255);
                    if (copy_from_user(buf, native, 255))
                        break;
                    else {
                        if(strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                            strcpy(ssh_connection, buf + 15);
                        } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                            strcpy(ld_preload, buf + 11);
                        }
                    }
                }
            }
        }

        data->ssh_connection = ssh_connection;
        data->ld_preload = ld_preload;

        if (likely(argv_len > 0))
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        error = user_path_at(AT_FDCWD, (const char __user *)p_get_arg1(regs), LOOKUP_FOLLOW, &exe_file);
        if (unlikely(error)) {
            abs_path = "-1";
        } else {
            exe_file_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
            if (unlikely(!exe_file_buf)) {
                abs_path = "-2";
            } else {
                abs_path = d_path(&exe_file, exe_file_buf, PATH_MAX);
                if (unlikely(IS_ERR(abs_path)))
                    abs_path = "-1";
            }
            path_put(&exe_file);
         }

        data->argv = argv_res_tmp;
        data->abs_path = abs_path;

        if(likely(argv_len > 0))
            kfree(argv_res);
    }
    return 0;
}

int compat_execveat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, error = 0;
    int env_len = 0;
    char *exe_file_buf = "-2";
    char *argv_res = NULL;
    char *abs_path = NULL;
    char *argv_res_tmp = NULL;
    const char __user *native;
    if (share_mem_flag != -1) {
        char *ssh_connection = NULL;
        char *ld_preload = NULL;
        struct execve_data *data;
        struct path exe_file;

        struct user_arg_ptr argv_ptr = {
            .is_compat = true,
        	.ptr.compat = (const compat_uptr_t __user *)p_get_arg3(regs),
        };

        struct user_arg_ptr env_ptr = {
            .is_compat = true,
        	.ptr.compat = (const compat_uptr_t __user *)p_get_arg4(regs),
        };

        data = (struct execve_data *)ri->data;

        env_len = count(env_ptr, MAX_ARG_STRINGS);
        argv_res_len = 128 * (argv_len + 2);
        argv_len = count(argv_ptr, MAX_ARG_STRINGS);

        if(likely(argv_len > 0)) {
            argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
            for (i = 0; i < argv_len; i++) {
                native = get_user_arg_ptr(argv_ptr, i);
                if (unlikely(IS_ERR(native)))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if (!len)
                    break;

                if (offset + len > argv_res_len + 1)
                    break;

                if (copy_from_user(argv_res + offset, native, len))
                    break;

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }
        
        ssh_connection = kzalloc(255, GFP_ATOMIC);
        ld_preload = kzalloc(255, GFP_ATOMIC);
        
        if(likely(env_len > 0)) {
            char buf[256];
            for (i = 0; i < env_len; i++) {
                native = get_user_arg_ptr(env_ptr, i);
                if (unlikely(IS_ERR(native)))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;
                else if(len > 14) {
                    memset(buf, 0, 255);
                    if (copy_from_user(buf, native, 255))
                        break;
                    else {
                        if(strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                            strcpy(ssh_connection, buf + 15);
                        } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                            strcpy(ld_preload, buf + 11);
                        }
                    }
                }
            }
        }

        data->ssh_connection = ssh_connection;
        data->ld_preload = ld_preload;

        if (likely(argv_len > 0))
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        error = user_path_at(AT_FDCWD, (const char __user *)p_get_arg2(regs), LOOKUP_FOLLOW, &exe_file);
        if (unlikely(error)) {
            abs_path = "-1";
        } else {
            exe_file_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
            if (unlikely(!exe_file_buf)) {
                abs_path = "-2";
            } else {
                abs_path = d_path(&exe_file, exe_file_buf, PATH_MAX);
                if (unlikely(IS_ERR(abs_path)))
                    abs_path = "-1";
            }
            path_put(&exe_file);
         }

        data->argv = argv_res_tmp;
        data->abs_path = abs_path;

        if(likely(argv_len > 0))
            kfree(argv_res);
    }
    return 0;
}
#endif

int execveat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, error = 0;
    int env_len = 0;
    char *exe_file_buf = "-2";
    char *argv_res = NULL;
    char *abs_path = NULL;
    char *argv_res_tmp = NULL;
    const char __user *native;
    if (share_mem_flag != -1) {
        char *ssh_connection = NULL;
        char *ld_preload = NULL;
        struct execve_data *data;
        struct path exe_file;
    	struct user_arg_ptr argv_ptr = {.ptr.native = (const char * const*) p_get_arg3(regs)};
    	struct user_arg_ptr env_ptr = {.ptr.native = (const char * const*) p_get_arg4(regs)};
        data = (struct execve_data *)ri->data;

        env_len = count(env_ptr, MAX_ARG_STRINGS);
        argv_len = count(argv_ptr, MAX_ARG_STRINGS);
        argv_res_len = 128 * (argv_len + 2);

        if(likely(argv_len > 0)) {
            argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
            for (i = 0; i < argv_len; i++) {
                native = get_user_arg_ptr(argv_ptr, i);
                if (unlikely(IS_ERR(native)))
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
        }

        ssh_connection = kzalloc(255, GFP_ATOMIC);
        ld_preload = kzalloc(255, GFP_ATOMIC);

        if(likely(env_len > 0)) {
            char buf[256];
            for (i = 0; i < env_len; i++) {
                native = get_user_arg_ptr(env_ptr, i);
                if (unlikely(IS_ERR(native)))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;
                else if(len > 14) {
                    memset(buf, 0, 255);
                    if (copy_from_user(buf, native, 255))
                        break;
                    else {
                        if(strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                            strcpy(ssh_connection, buf + 15);
                        } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                            strcpy(ld_preload, buf + 11);
                        }
                    }
                }
            }
        }

        data->ssh_connection = ssh_connection;
        data->ld_preload = ld_preload;

        if (likely(argv_len > 0))
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        error = user_path_at(AT_FDCWD, (const char __user *)p_get_arg2(regs), LOOKUP_FOLLOW, &exe_file);
        if (unlikely(error)) {
            abs_path = "-1";
        } else {
            exe_file_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
            if (unlikely(!exe_file_buf)) {
                abs_path = "-2";
            } else {
                abs_path = d_path(&exe_file, exe_file_buf, PATH_MAX);
                if (unlikely(IS_ERR(abs_path)))
                    abs_path = "-1";
            }
            path_put(&exe_file);
         }

        data->argv = argv_res_tmp;
        data->abs_path = abs_path;

        if(likely(argv_len > 0))
            kfree(argv_res);
    }
    return 0;
}

int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, error = 0;
    int env_len = 0;
    char *exe_file_buf = "-2";
    char *argv_res = NULL;
    char *abs_path = NULL;
    char *argv_res_tmp = NULL;
    const char __user *native;
    if (share_mem_flag != -1) {
        char *ssh_connection = NULL;
        char *ld_preload = NULL;
        struct execve_data *data;
        struct path exe_file;
    	struct user_arg_ptr argv_ptr = {.ptr.native = (const char * const*) p_get_arg2(regs)};
    	struct user_arg_ptr env_ptr = {.ptr.native = (const char * const*) p_get_arg3(regs)};
        data = (struct execve_data *)ri->data;

        argv_len = count(argv_ptr, MAX_ARG_STRINGS);
        argv_res_len = 128 * (argv_len + 2);
        env_len = count(env_ptr, MAX_ARG_STRINGS);

        if(likely(argv_len > 0)) {
            argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
            for (i = 0; i < argv_len; i++) {
                native = get_user_arg_ptr(argv_ptr, i);
                if (unlikely(IS_ERR(native)))
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
        }

        ssh_connection = kzalloc(255, GFP_ATOMIC);
        ld_preload = kzalloc(255, GFP_ATOMIC);

        if(likely(env_len > 0)) {
            char buf[256];
            for (i = 0; i < env_len; i++) {
                native = get_user_arg_ptr(env_ptr, i);
                if (unlikely(IS_ERR(native)))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;
                else if(len > 14) {
                    memset(buf, 0, 255);
                    if (copy_from_user(buf, native, 255))
                        break;
                    else {
                        if(strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                            strcpy(ssh_connection, buf + 15);
                        } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                            strcpy(ld_preload, buf + 11);
                        }
                    }
                }
            }
        }

        data->ssh_connection = ssh_connection;
        data->ld_preload = ld_preload;

        if (likely(argv_len > 0))
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        error = user_path_at(AT_FDCWD, (const char __user *)p_get_arg1(regs), LOOKUP_FOLLOW, &exe_file);
        if (unlikely(error)) {
            abs_path = "-1";
        } else {
            exe_file_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
            if (unlikely(!exe_file_buf)) {
                abs_path = "-2";
            } else {
                abs_path = d_path(&exe_file, exe_file_buf, PATH_MAX);
                if (unlikely(IS_ERR(abs_path)))
                    abs_path = "-1";
            }
            path_put(&exe_file);
         }

        data->argv = argv_res_tmp;
        data->abs_path = abs_path;

        if(likely(argv_len > 0))
            kfree(argv_res);
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
	    pid_t socket_pid = -1;
	    int socket_check = 0;
	    int tty_name_len = 0;
	    const char *d_name = "-1";
	    int sa_family = -1;
        char *pid_tree = "-1";
        char *pname_buf = "-2";
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
        argv = data -> argv;
        abs_path = data -> abs_path;

	    sessionid = get_sessionid();

        if(strlen(current->comm) > 0)
            comm = str_replace(current->comm, "\n", " ");
        else
            comm = "";

        pid_tree = get_pid_tree();
        tty = get_current_tty();

        if(tty) {
            tty_name_len = strlen(tty_name);
            if(tty_name_len == 0) {
                tty_name = "-1";
            } else {
                tty_name = tty->name;
            }
        } else
            tty_name = "-1";

        task = current;
        while(task->pid != 1) {
            task_files = files_fdtable(task->files);

            for (i = 0; task_files->fd[i] != NULL; i++) {
                if(i>20)
                    break;

                d_name = d_path(&(task_files->fd[i]->f_path), fd_buff, 24);
                if (IS_ERR(d_name)) {
                    d_name = "-1";
                    continue;
                }

                if(strncmp("socket:[", d_name, 8) == 0) {
                    socket = (struct socket *)task_files->fd[i]->private_data;
                    if(likely(socket)) {
                        sk = socket->sk;
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
                                snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_daddr));
                                snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_rcv_saddr));
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
                socket_pid = task->pid;
                socket_pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
                if (unlikely(!socket_pname_buf)) {
                    socket_pname = "-2";
                } else {
                    socket_pname = get_exe_file(task, socket_pname_buf, PATH_MAX);
                    if (unlikely(!socket_pname)) {
                        socket_pname = "-1";
                    }
                }
                break;
            } else {
                task = task->parent;
            }
        }

        files = files_fdtable(current->files);
        if(likely(files->fd[0] != NULL)) {
            tmp_stdin = d_path(&(files->fd[0]->f_path), stdin_fd_buf, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdin))) {
                tmp_stdin = "-1";
            }
        } else {
            tmp_stdin = "";
        }

        if(likely(files->fd[1] != NULL)) {
            tmp_stdout = d_path(&(files->fd[1]->f_path), stdout_fd_buf, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdout))) {
                tmp_stdout = "-1";
            }
        } else {
            tmp_stdout = "";
        }

        pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
        if (unlikely(!pname_buf)) {
            pname = "-2";
        } else {
            pname = get_exe_file(current, pname_buf, PATH_MAX);
        }

        result_str_len = strlen(argv) + strlen(pname) + strlen(abs_path) + strlen(pid_tree) + tty_name_len +
                         strlen(comm) + strlen(current->nsproxy->uts_ns->name.nodename) + strlen(data->ssh_connection) +
                         strlen(data->ld_preload) + 256;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);

        snprintf(result_str, result_str_len,
                 "%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%u%s%s%s%s%s%s%s%s%s%d%s%s%s%s%s%d%s%s%s%s%s%s",
                 get_current_uid(), "\n", EXECVE_TYPE, "\n", pname, "\n",
                 abs_path, "\n", argv, "\n", current->pid, "\n",
                 current->real_parent->pid, "\n", pid_vnr(task_pgrp(current)),
                 "\n", current->tgid, "\n", comm, "\n",
                 current->nsproxy->uts_ns->name.nodename,"\n",tmp_stdin,"\n",tmp_stdout,
                 "\n", sessionid, "\n", dip, "\n", dport,"\n", sip,"\n", sport,"\n", sa_family,
                 "\n", pid_tree, "\n", tty_name,"\n", socket_pid, "\n", socket_pname, "\n",
                 data->ssh_connection, "\n", data->ld_preload);

        send_msg_to_user(result_str, 1);

        if (likely(strcmp(pname_buf, "-2")))
            kfree(pname_buf);

        if (likely(strcmp(socket_pname_buf, "-2")))
            kfree(socket_pname_buf);

        kfree(data->ld_preload);
        kfree(data->ssh_connection);
        kfree(pid_tree);
	}
	return 0;
}
#else

struct execve_data {
    char *argv;
    char *ssh_connection;
    char *ld_preload;
};

int compat_execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0;
    int env_len = 0;
    char *argv_res = NULL;
    char *argv_res_tmp = NULL;
    const char __user *native;
    if (share_mem_flag != -1) {
        char *ssh_connection = NULL;
        char *ld_preload = NULL;
        struct execve_data *data;
        char **argv = (char **) p_get_arg2(regs);
        char **env = (char **) p_get_arg3(regs);
        data = (struct execve_data *)ri->data;

        env_len = count(env, MAX_ARG_STRINGS);
        argv_res_len = 128 * (argv_len + 2);
        argv_len = count(argv, MAX_ARG_STRINGS);

        if(likely(argv_len > 0)) {
            argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
            for(i = 0; i < argv_len; i ++) {
                if(get_user(native, argv + i))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;

                if(offset + len > argv_res_len - 1)
                    break;

                if (copy_from_user(argv_res + offset, native, len))
                    break;

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }

        ssh_connection = kzalloc(255, GFP_ATOMIC);
        ld_preload = kzalloc(255, GFP_ATOMIC);

        if(likely(env_len > 0)) {
            char buf[256];
            for(i = 0; i < argv_len; i ++) {
                if(get_user(native, env + i))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;
                else if(len > 14) {
                    memset(buf, 0, 255);
                    if (copy_from_user(buf, native, 255))
                        break;
                    else {
                        if(strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                            strcpy(ssh_connection, buf + 15);
                        } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                            strcpy(ld_preload, buf + 11);
                        }
                    }
                }
            }
        }

        data->ssh_connection = ssh_connection;
        data->ld_preload = ld_preload;

        if (likely(argv_len > 0))
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        data->argv = argv_res_tmp;

        if(likely(argv_len > 0))
            kfree(argv_res);
    }
    return 0;
}

int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0;
    char *argv_res = NULL;
    int env_len = 0;
    char *argv_res_tmp = NULL;
    const char __user *native;
    if (share_mem_flag != -1) {
        char *ssh_connection = NULL;
        char *ld_preload = NULL;
        struct execve_data *data;
        char **argv = (char **) p_get_arg2(regs);
        char **env = (char **) p_get_arg3(regs);
        data = (struct execve_data *)ri->data;

        argv_res_len = 128 * (argv_len + 2);
        argv_len = count(argv, MAX_ARG_STRINGS);
        env_len = count(env, MAX_ARG_STRINGS);

        if(likely(argv_len > 0)) {
            argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
            for(i = 0; i < argv_len; i ++) {
                if(get_user(native, argv + i))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;

                if(offset + len > argv_res_len - 1)
                    break;

                if (copy_from_user(argv_res + offset, native, len))
                    break;

                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }

        ssh_connection = kzalloc(255, GFP_ATOMIC);
        ld_preload = kzalloc(255, GFP_ATOMIC);

        if(likely(env_len > 0)) {
            char buf[256];
            for(i = 0; i < env_len; i ++) {
                if(get_user(native, env + i))
                    break;

                len = strnlen_user(native, MAX_ARG_STRLEN);
                if(!len)
                    break;
                else if(len > 14) {
                    memset(buf, 0, 255);
                    if (copy_from_user(buf, native, 255))
                        break;
                    else {
                        if(strncmp("SSH_CONNECTION=", buf, 15) == 0) {
                            strcpy(ssh_connection, buf + 15);
                        } else if(strncmp("LD_PRELOAD=", buf, 11) == 0) {
                            strcpy(ld_preload, buf + 11);
                        }
                    }
                }
            }
        }

        data->ssh_connection = ssh_connection;
        data->ld_preload = ld_preload;

        if(likely(argv_len > 0))
            argv_res_tmp = str_replace(argv_res, "\n", " ");
        else
            argv_res_tmp = "";

        data->argv = argv_res_tmp;

        if(likely(argv_len > 0))
            kfree(argv_res);
    }
    return 0;
}

int execve_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
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
		int socket_check = 0;
		int tty_name_len = 0;
    	char *pid_tree;
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

        data = (struct execve_data *)ri->data;
        argv = data -> argv;

        sessionid = get_sessionid();

        if(strlen(current->comm) > 0)
            comm = str_replace(current->comm, "\n", " ");
        else
            comm = "";

        tty = get_current_tty();
        if(tty) {
            tty_name_len = strlen(tty->name);
            if(tty_name_len == 0) {
                tty_name = "-1";
            } else {
                tty_name = tty->name;
            }
        } else
            tty_name = "-1";

        pid_tree = get_pid_tree();

        task = current;
        while(task->pid != 1) {
            task_files = files_fdtable(task->files);

            for (i = 0; task_files->fd[i] != NULL; i++) {
                if(i > 20)
                    break;

                d_name = d_path(&(task_files->fd[i]->f_path), fd_buff, 24);
                if (IS_ERR(d_name)) {
                    d_name = "-1";
                    continue;
                }

                if(strncmp("socket:[", d_name, 8) == 0) {
                    socket = (struct socket *)task_files->fd[i]->private_data;
                    if(likely(socket)) {
                        sk = socket->sk;
                        inet = (struct inet_sock*)sk;
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
                                snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_daddr));
                                snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sk->sk_v6_rcv_saddr));
                                snprintf(sport, 16, "%d", Ntohs(inet->inet_sport));
                                snprintf(dport, 16, "%d", Ntohs(inet->inet_dport));
                            #else
                                snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(inet->pinet6->daddr));
                                snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(inet->pinet6->saddr));
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
                socket_pid = task->pid;
                socket_pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
                if (unlikely(!socket_pname_buf)) {
                    socket_pname = "-2";
                } else {
                    socket_pname = get_exe_file(task, socket_pname_buf, PATH_MAX);
                    if (unlikely(!socket_pname)) {
                        socket_pname = "-1";
                    }
                }
                break;
            } else {
                task = task->parent;
            }
        }

        files = files_fdtable(current->files);
        if(likely(files->fd[0] != NULL)) {
            tmp_stdin = d_path(&(files->fd[0]->f_path), tmp_stdin_fd, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdin))) {
                tmp_stdin = "-1";
            }
        } else {
            tmp_stdin = "";
        }

        if(likely(files->fd[1] != NULL)) {
            tmp_stdout = d_path(&(files->fd[1]->f_path), tmp_stdout_fd, PATH_MAX);
            if (unlikely(IS_ERR(tmp_stdout))) {
                tmp_stdout = "-1";
            }
        } else {
            tmp_stdout = "";
        }

        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        if (unlikely(!buffer)) {
            abs_path = "-2";
        } else {
            abs_path = get_exe_file(current, buffer, PATH_MAX);
        }

        pname = _dentry_path_raw();

        result_str_len = strlen(argv) + strlen(pname) +
                         strlen(abs_path) + strlen(comm) + strlen(pid_tree) + tty_name_len +
                         strlen(current->nsproxy->uts_ns->name.nodename) + strlen(data->ssh_connection) +
                         strlen(data->ld_preload) + 256;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);

        snprintf(result_str, result_str_len,
                 "%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%u%s%s%s%s%s%s%s%s%s%d%s%s%s%s%s%d%s%s%s%s%s%s",
                 get_current_uid(), "\n", EXECVE_TYPE, "\n", pname, "\n",
                 abs_path, "\n", argv, "\n", current->pid, "\n",
                 current->real_parent->pid, "\n", pid_vnr(task_pgrp(current)),
                 "\n", current->tgid, "\n", comm, "\n",
                 current->nsproxy->uts_ns->name.nodename,"\n",tmp_stdin,"\n",tmp_stdout,
                 "\n", sessionid, "\n", dip, "\n", dport,"\n", sip,"\n", sport,"\n", sa_family,
                 "\n", pid_tree, "\n", tty_name,"\n", socket_pid, "\n", socket_pname, "\n",
                 data->ssh_connection, "\n", data->ld_preload);

        send_msg_to_user(result_str, 1);

        if (likely(strcmp(buffer, "-2")))
            kfree(buffer);

        if (likely(strcmp(socket_pname_buf, "-2")))
            kfree(socket_pname_buf);

        kfree(data->ld_preload);
        kfree(data->ssh_connection);
        kfree(pid_tree);
	}

	return 0;
}
#endif

struct security_inode_create_data {
    char *filename;
    char *pname_buf;
};

int security_inode_create_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        char *result_str;
        char *pname_buf;
        struct security_inode_create_data *data;
        pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
        data = (struct security_inode_create_data *)ri->data;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        result_str = dentry_path_raw((struct dentry *) p_regs_get_arg2(regs),pname_buf,PATH_MAX);
    #else
        result_str = __dentry_path((struct dentry *) p_regs_get_arg2(regs),pname_buf,PATH_MAX);
    #endif
        data->filename = result_str;
        data->pname_buf = pname_buf;
    }
    return 0;
}

int security_inode_create_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned int sessionid;
    char *result_str = NULL;
    int result_str_len;
    char *comm = NULL;
    if (share_mem_flag != -1) {
        struct security_inode_create_data *data;
        char *buffer = NULL;
        char *pathstr = NULL;
        char *abs_path = NULL;

        data = (struct security_inode_create_data *)ri->data;
        pathstr = data->filename;
        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        abs_path = get_exe_file(current, buffer, PATH_MAX);

        sessionid = get_sessionid();

        if(strlen(current->comm) > 0)
            comm = str_replace(current->comm, "\n", " ");
        else
            comm = "";

        result_str_len = strlen(current->nsproxy->uts_ns->name.nodename)
                            + strlen(comm) + strlen(abs_path) + 172;
        if(likely(pathstr))
            result_str_len = result_str_len + strlen(pathstr);
        else
            pathstr = "";

        result_str = kzalloc(result_str_len, GFP_ATOMIC);

        snprintf(result_str, result_str_len,
                "%d%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                get_current_uid(), "\n", CREATE_FILE, "\n", abs_path, "\n", pathstr,
                "\n", current->pid, "\n",current->real_parent->pid, "\n",
                pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);
        send_msg_to_user(result_str, 1);
        kfree(data->pname_buf);
        kfree(buffer);
    }
    return 0;
}

void ptrace_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int result_str_len;
    long request;
    long pid;
    void *addr;
    char *data;
    char *abs_path = NULL;
    char *result_str = NULL;
    char *comm = NULL;
    char *buffer = NULL;
    unsigned int sessionid;

	request = (long) p_get_arg1(regs);
	if (share_mem_flag != -1) {
	    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        	pid = (long) p_get_arg2(regs);
        	addr = (void *) p_get_arg3(regs);
        	data = (char *) p_get_arg4(regs);
	        sessionid = get_sessionid();

            buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
            abs_path = get_exe_file(current, buffer, PATH_MAX);

            if(strlen(current->comm) > 0)
                comm = str_replace(current->comm, "\n", " ");
            else
                comm = "";

            result_str_len = strlen(current->nsproxy->uts_ns->name.nodename) +
                             strlen(comm) + strlen(abs_path) + 172;

            result_str = kzalloc(result_str_len, GFP_ATOMIC);

            snprintf(result_str, result_str_len,
                     "%d%s%s%s%ld%s%ld%s%p%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                     get_current_uid(), "\n", PTRACE_TYPE, "\n", request,
                     "\n", pid, "\n", addr, "\n", &data, "\n", abs_path, "\n",
                     current->pid, "\n", current->real_parent->pid, "\n",
                     pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                     comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);

            send_msg_to_user(result_str, 1);
            kfree(buffer);
	    }
	}
}

int recvfrom_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct recvfrom_data *data;
    if (share_mem_flag != -1) {
        data = (struct recvfrom_data *)ri->data;
        data->fd = p_get_arg1(regs);
        data->ubuf = (void *)p_get_arg2(regs);
        data->size = (size_t)p_get_arg3(regs);
        data->dirp = (struct sockaddr *)p_get_arg5(regs);
        data->addr_len = (int)p_get_arg6(regs);
    }
    return 0;
}

int recvfrom_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int err;
    int flag = 0;
    int sa_family = 0;
    int copy_res = 0;
    int recv_data_copy_res = 0;
    int result_str_len;
    int opcode = 0;
    int qr;
    int rcode = 0;
    int addrlen;
    unsigned int sessionid;
    char *comm = NULL;
    char dip[64];
    char dport[16];
    char sip[64] = "-1";
    char sport[16] = "-1";
    unsigned char *recv_data = NULL;
    char *query = NULL;
    char *abs_path = NULL;
    char *result_str = NULL;
    char *buffer = NULL;

	if (share_mem_flag != -1) {
	    struct recvfrom_data *data;
        struct sockaddr tmp_dirp;
        struct sockaddr_in *sin;
        struct sockaddr_in6 *sin6;
        struct socket *sock;
        struct sockaddr_in source_addr;
        struct sockaddr_in6 source_addr6 = {};
	    data = (struct recvfrom_data *)ri->data;
        addrlen = data->addr_len;

	    copy_res = copy_from_user(&tmp_dirp, data->dirp, 16);
        if (unlikely(copy_res != 0))
            return 0;

        sessionid = get_sessionid();

        if (tmp_dirp.sa_family == AF_INET) {
            sa_family = AF_INET;
            sock = sockfd_lookup(data->fd, &err);

            if (unlikely(IS_ERR(sock)))
                goto out;

            sin = (struct sockaddr_in *)&tmp_dirp;
            if (sin->sin_port == 13568 || sin->sin_port == 59668) {
                recv_data = kzalloc(data->size, GFP_ATOMIC);
                recv_data_copy_res = copy_from_user(recv_data, data->ubuf, data->size);
                if (sizeof(recv_data) >= 8) {
    	            qr = (recv_data[2] & 0x80) ? 1 : 0;

    	            if (qr == 1 ) {
    	    	        flag = 1;
    	                opcode = (recv_data[2] >> 3) & 0x0f;
    	    	        rcode = recv_data[3] & 0x0f;
    	    	        query = kzalloc(strlen(recv_data+12), GFP_ATOMIC);
    	    	        getDNSQuery(recv_data, 12, query);
    	    	        snprintf(dip, 64, "%d.%d.%d.%d", NIPQUAD(sin->sin_addr.s_addr));
                        snprintf(dport, 16, "%d", Ntohs(sin->sin_port));
                        if (sock) {
                        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
                            err = kernel_getsockname(sock, (struct sockaddr *)&source_addr);
                        #else
                            err = kernel_getsockname(sock, (struct sockaddr *)&source_addr, &addrlen);
                        #endif
                            if (likely(err == 0)) {
                                snprintf(sport, 16, "%d", Ntohs(source_addr.sin_port));
                                snprintf(sip, 64, "%d.%d.%d.%d", NIPQUAD(source_addr.sin_addr));
                                sockfd_put(sock);
                            }
                        }
    	            }
    	        }
            }
        } else if (tmp_dirp.sa_family == AF_INET6) {
            sa_family = AF_INET6;
            sock = sockfd_lookup(data->fd, &err);

            if (unlikely(IS_ERR(sock)))
                goto out;

            sin6 = (struct sockaddr_in6 *)&tmp_dirp;
            if (sin6->sin6_port == 13568 || sin6->sin6_port == 59668) {
                recv_data = kzalloc(data->size, GFP_ATOMIC);
                recv_data_copy_res = copy_from_user(recv_data, (void *)p_get_arg2(regs), data->size);

                if (sizeof(recv_data) >= 8) {
                    qr = (recv_data[2] & 0x80) ? 1 : 0;
    	            if (qr == 1 ) {
    	    	        flag = 1;
    	                opcode = (recv_data[2] >> 3) & 0x0f;
    	    	        rcode = recv_data[3] & 0x0f;
    	    	        query = kzalloc(strlen(recv_data+12), GFP_ATOMIC);
    	    	        getDNSQuery(recv_data, 12, query);
    	    	        snprintf(dip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(sin6->sin6_addr));
                        snprintf(dport, 16, "%d", Ntohs(sin6->sin6_port));
                        if (sock) {
                        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
                            err = kernel_getsockname(sock, (struct sockaddr *)&source_addr);
                        #else
                            err = kernel_getsockname(sock, (struct sockaddr *)&source_addr, &addrlen);
                        #endif
                            if (likely(err == 0)) {
                                snprintf(sport, 16, "%d", Ntohs(source_addr6.sin6_port));
                                snprintf(sip, 64, "%d:%d:%d:%d:%d:%d:%d:%d", NIP6(source_addr6.sin6_addr));
                                sockfd_put(sock);
                            }
                        }
    	            }
                }
            }
        }

        if (flag == 1) {
            buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
            abs_path = get_exe_file(current, buffer, PATH_MAX);

            if(strlen(current->comm) > 0)
                comm = str_replace(current->comm, "\n", " ");
            else
                comm = "";

            result_str_len = strlen(query) + strlen(current->nsproxy->uts_ns->name.nodename) +
                             strlen(comm) + strlen(abs_path) + 172;

            result_str = kzalloc(result_str_len, GFP_ATOMIC);

            snprintf(result_str, result_str_len,
                     "%d%s%s%s%d%s%d%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%s%s%s%s%d%s%d%s%d%s%s%s%u",
                     get_current_uid(), "\n", DNS_TYPE, "\n", sa_family,
                     "\n", data->fd, "\n", dport, "\n", dip, "\n", abs_path, "\n",
                     current->pid, "\n", current->real_parent->pid, "\n",
                     pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                     comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n",
                     sip, "\n", sport, "\n", qr, "\n", opcode, "\n", rcode, "\n", query, "\n", sessionid);

            send_msg_to_user(result_str, 1);
            kfree(query);
            kfree(recv_data);
            kfree(buffer);
        }
	}
    return 0;

out:
    return 0;
}

void load_module_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int i = 0;
    int result_str_len;
    unsigned int sessionid;
    char *cwd = NULL;
    char *result_str = NULL;
    char *comm = NULL;
    char *buffer = NULL;

	if (share_mem_flag != -1) {
	    struct path files_path;
        struct files_struct *current_files;
        struct fdtable *files_table;
	    char *abs_path = NULL;
	    char init_module_buf[PATH_MAX];
	    memset(init_module_buf, 0, PATH_MAX);

        sessionid = get_sessionid();
        current_files = current->files;
        files_table = files_fdtable(current_files);

        while (files_table->fd[i] != NULL)
            i++;

        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        abs_path = get_exe_file(current, buffer, PATH_MAX);

        files_path = files_table->fd[i - 1]->f_path;
        cwd = d_path(&files_path, init_module_buf, PATH_MAX);

        if(strlen(current->comm) > 0)
            comm = str_replace(current->comm, "\n", " ");
        else
            comm = "";

        result_str_len = strlen(cwd) + strlen(current->nsproxy->uts_ns->name.nodename)
                         + strlen(comm) + strlen(abs_path) + 192;

        result_str = kzalloc(result_str_len, GFP_ATOMIC);

        snprintf(result_str, result_str_len, "%d%s%s%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%s%s%u",
                 get_current_uid(), "\n", LOAD_MODULE_TYPE, "\n",abs_path,"\n" ,cwd ,
                 "\n", current->pid, "\n", current->real_parent->pid, "\n",
                 pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                 comm, "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);

        send_msg_to_user(result_str, 1);
        kfree(buffer);
	}
}

struct update_cred_data {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    uid_t old_uid;
#else
    int old_uid;
#endif
};

int update_cred_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        struct update_cred_data *data;
        data = (struct update_cred_data *)ri->data;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
        data->old_uid = current->real_cred->uid.val;
    #else
        data->old_uid = current->real_cred->uid;
    #endif
    }
    return 0;
}

int update_cred_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        int now_uid;
        now_uid = get_current_uid();

        if(now_uid == 0) {
	        struct update_cred_data *data;
	        char *comm = NULL;
	        char *buffer = NULL;
            data = (struct update_cred_data *)ri->data;

            if(data->old_uid != 0) {
                if(strlen(current->comm) > 0)
                    comm = str_replace(current->comm, "\n", " ");
                else
                    comm = "";

                if (strcmp(comm, "sudo") != 0 && strcmp(comm, "su") != 0 && strcmp(comm, "sshd") != 0) {
                    int result_str_len;
                    unsigned int sessionid;
                    char *result_str = NULL;
                    char *abs_path;

                    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
                    abs_path = get_exe_file(current, buffer, PATH_MAX);

                    sessionid = get_sessionid();

                    result_str_len = strlen(current->nsproxy->uts_ns->name.nodename)
                                     + strlen(comm) + strlen(abs_path) + 192;

                    result_str = kzalloc(result_str_len, GFP_ATOMIC);

                    snprintf(result_str, result_str_len, "%d%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%d%s%s%s%u",
                             get_current_uid(), "\n", UPDATE_CRED_TYPE, "\n",abs_path,
                             "\n", current->pid, "\n", current->real_parent->pid, "\n",
                             pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                             comm, "\n", data->old_uid, "\n", current->nsproxy->uts_ns->name.nodename,
                             "\n", sessionid);

                    send_msg_to_user(result_str, 1);
                    kfree(buffer);
                }
            }
        }
    }
    return 0;
}

struct mprotect_data {
    unsigned long start;
    size_t len;
    unsigned long prot;
};

int mprotect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        struct mprotect_data *data;
        data = (struct mprotect_data *)ri->data;
        data->start = (unsigned long)p_get_arg1(regs);
        data->len = (size_t)p_get_arg2(regs);
        data->prot = (unsigned long)p_get_arg3(regs);
    }
    return 0;
}

int mprotect_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (share_mem_flag != -1) {
        int retval;
        struct mprotect_data *data;
        data = (struct mprotect_data *)ri->data;
        unsigned long prot = data->prot;
        retval = regs_return_value(regs);
        if(retval == 0) {
            if(prot & PROT_READ || prot & PROT_EXEC) {
                unsigned int sessionid;
                int result_str_len;
                char *buffer = NULL;
                char *comm = NULL;
                char *result_str = NULL;
                char *abs_path;

                if(strlen(current->comm) > 0)
                    comm = str_replace(current->comm, "\n", " ");
                else
                    comm = "";

                sessionid = get_sessionid();

                buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
                abs_path = get_exe_file(current, buffer, PATH_MAX);

                result_str_len = strlen(current->nsproxy->uts_ns->name.nodename)
                                 + strlen(comm) + strlen(abs_path) + 192;

                result_str = kzalloc(result_str_len, GFP_ATOMIC);
                snprintf(result_str, result_str_len, "%d%s%s%s%s%s%d%s%d%s%d%s%d%s%s%s%lu%s%u%s%lu%s%s%s%u",
                         get_current_uid(), "\n", MPROTECT_TYPE, "\n", abs_path,
                         "\n", current->pid, "\n", current->real_parent->pid, "\n",
                         pid_vnr(task_pgrp(current)), "\n", current->tgid, "\n",
                         comm, "\n", data->start, "\n", data->len, "\n", data->prot,
                         "\n", current->nsproxy->uts_ns->name.nodename, "\n", sessionid);

                send_msg_to_user(result_str, 1);
                kfree(buffer);
            }
        }
    }
    return 0;
}

struct kretprobe connect_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(connect),
    .data_size  = sizeof(struct connect_data),
	.handler = connect_handler,
    .entry_handler = connect_entry_handler,
    .maxactive = 40,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
struct kretprobe execveat_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
    .data_size  = sizeof(struct execve_data),
	.handler = execve_handler,
	.entry_handler = execveat_entry_handler,
	.maxactive = 40,
};
#endif

struct kretprobe execve_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(execve),
    .data_size  = sizeof(struct execve_data),
	.handler = execve_handler,
	.entry_handler = execve_entry_handler,
	.maxactive = 40,
};

#ifdef CONFIG_COMPAT
struct kretprobe compat_execve_kretprobe = {
    .kp.symbol_name = P_GET_COMPAT_SYSCALL_NAME(execve),
    .data_size  = sizeof(struct execve_data),
	.handler = execve_handler,
	.entry_handler = compat_execve_entry_handler,
	.maxactive = 40,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
struct kretprobe compat_execveat_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
    .data_size  = sizeof(struct execve_data),
	.handler = execve_handler,
	.entry_handler = compat_execveat_entry_handler,
	.maxactive = 40,
};
#endif
#endif

struct kretprobe security_inode_create_kretprobe = {
    .kp.symbol_name = "security_inode_create",
    .data_size = sizeof(struct security_inode_create_data),
	.handler = security_inode_create_handler,
	.entry_handler = security_inode_create_entry_handler,
	.maxactive = 40,
};

struct kprobe ptrace_kprobe = {
    .symbol_name = P_GET_SYSCALL_NAME(ptrace),
	.post_handler = ptrace_post_handler,
};

struct kretprobe recvfrom_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(recvfrom),
    .data_size  = sizeof(struct recvfrom_data),
	.handler = recvfrom_handler,
	.entry_handler = recvfrom_entry_handler,
	.maxactive = 40,
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
	.maxactive = 40,
};

struct kretprobe mprotect_kretprobe = {
    .kp.symbol_name = P_GET_SYSCALL_NAME(mprotect),
    .data_size  = sizeof(struct mprotect_data),
  	.handler = mprotect_handler,
  	.entry_handler = mprotect_entry_handler,
  	.maxactive = 40,
};

int connect_register_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&connect_kretprobe);

	if (ret == 0)
        connect_kprobe_state = 0x1;

	return ret;
}

void unregister_kretprobe_connect(void)
{
	unregister_kretprobe(&connect_kretprobe);
}

int execve_register_kprobe(void)
{
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

void unregister_kprobe_execve(void)
{
	unregister_kretprobe(&execve_kretprobe);
}

int create_file_register_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&security_inode_create_kretprobe);
	if (ret == 0)
        create_file_kprobe_state = 0x1;

	return ret;
}

void unregister_kprobe_create_file(void)
{
	unregister_kretprobe(&security_inode_create_kretprobe);
}

int ptrace_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&ptrace_kprobe);

	if (ret == 0)
        ptrace_kprobe_state = 0x1;

	return ret;
}

void unregister_kprobe_ptrace(void)
{
	unregister_kprobe(&ptrace_kprobe);
}

int recvfrom_register_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&recvfrom_kretprobe);

	if (ret == 0)
        recvfrom_kprobe_state = 0x1;

	return ret;
}

void unregister_kprobe_recvfrom(void)
{
	unregister_kretprobe(&recvfrom_kretprobe);
}

int load_module_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&load_module_kprobe);

	if (ret == 0)
        load_module_kprobe_state = 0x1;

	return ret;
}

void unregister_kprobe_load_module(void)
{
	unregister_kprobe(&load_module_kprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
void unregister_kprobe_execveat(void)
{
	unregister_kretprobe(&execveat_kretprobe);
}
#endif

int update_cred_register_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&update_cred_kretprobe);
	if (ret == 0)
        update_cred_kprobe_state = 0x1;

	return ret;
}

void unregister_kprobe_update_cred(void)
{
	unregister_kretprobe(&update_cred_kretprobe);
}

int mprotect_register_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&mprotect_kretprobe);

	if (ret == 0)
        mprotect_kprobe_state = 0x1;

	return ret;
}

void unregister_kprobe_mprotect(void)
{
	unregister_kretprobe(&mprotect_kretprobe);
}

void uninstall_kprobe(void)
{
    if (connect_kprobe_state == 0x1)
	    unregister_kretprobe_connect();

    if (execve_kprobe_state == 0x1)
	    unregister_kprobe_execve();

    if (create_file_kprobe_state == 0x1)
	    unregister_kprobe_create_file();

    if (ptrace_kprobe_state == 0x1)
	    unregister_kprobe_ptrace();

    if (recvfrom_kprobe_state == 0x1)
	    unregister_kprobe_recvfrom();

    if (load_module_kprobe_state == 0x1)
	    unregister_kprobe_load_module();

	if (update_cred_kprobe_state == 0x1)
	    unregister_kprobe_update_cred();

	if (mprotect_kprobe_state == 0x1)
	    unregister_kprobe_mprotect();

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

int __init smith_init(void)
{
	int ret;
	checkCPUendianRes = checkCPUendian();

    ret = init_share_mem();

    if (ret != 0)
        return ret;
    else
        printk(KERN_INFO "[SMITH] init_share_mem success \n");

    if (CONNECT_HOOK == 1) {
	    ret = connect_register_kprobe();
	    if (ret < 0) {
		    printk(KERN_INFO "[SMITH] connect register_kprobe failed, returned %d\n", ret);
	    }
	}

    if (EXECVE_HOOK == 1) {
	    ret = execve_register_kprobe();
	    if (ret < 0) {
		    printk(KERN_INFO "[SMITH] execve register_kprobe failed, returned %d\n", ret);
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
		    printk(KERN_INFO "[SMITH] create_file register_kprobe failed, returned %d\n", ret);
	    }
	}

    if (PTRACE_HOOK == 1) {
	    ret = ptrace_register_kprobe();
	    if (ret < 0) {
		    printk(KERN_INFO "[SMITH] ptrace register_kprobe failed, returned %d\n", ret);
	    }
	}

    if (DNS_HOOK == 1) {
	ret = recvfrom_register_kprobe();
	    if (ret < 0) {
		    printk(KERN_INFO "[SMITH] recvfrom register_kprobe failed, returned %d\n", ret);
	    }
	}

    if (LOAD_MODULE_HOOK == 1) {
	    ret = load_module_register_kprobe();
	    if (ret < 0) {
		    printk(KERN_INFO "[SMITH] load_module register_kprobe failed, returned %d\n", ret);
	    }
	}

	if (UPDATE_CRED_HOOK == 1) {
	    ret = update_cred_register_kprobe();
    	if (ret < 0) {
    	    printk(KERN_INFO "[SMITH] update_cred register_kprobe failed, returned %d\n", ret);
    	}
	}

	if (MPROTECT_HOOK == 1) {
	    ret = mprotect_register_kprobe();
        if (ret < 0) {
            printk(KERN_INFO "[SMITH] mprotect register_kprobe failed, returned %d\n", ret);
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

	printk(KERN_INFO "[SMITH] register_kprobe success: connect_hook: %d,load_module_hook:"
	                 " %d,execve_hook: %d,create_file_hook: %d,ptrace_hook: %d, update_cred_hook:"
	                 " %d, DNS_HOOK: %d,EXIT_PROTECT: %d,ROOTKIT_CHECK: %d\n",
	                 CONNECT_HOOK, LOAD_MODULE_HOOK, EXECVE_HOOK, CREATE_FILE_HOOK,
	                 PTRACE_HOOK, UPDATE_CRED_HOOK, DNS_HOOK, EXIT_PROTECT, ROOTKIT_CHECK);

	return 0;
}

void __exit smith_exit(void)
{
#if (ROOTKIT_CHECK == 1)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    anti_root_kit_exit();
#endif
#endif

	uninstall_kprobe();
	uninstall_share_mem();
	printk(KERN_INFO "[SMITH] uninstall_kprobe success\n");
}

module_init(smith_init)
module_exit(smith_exit)

MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.2.0");
MODULE_AUTHOR("E_Bwill <cy_sniper@yeah.net>");
MODULE_DESCRIPTION("get execve,connect,ptrace,load_module,dns_query,create_file,cred_change,"
                   "proc_file_hook,syscall_hook,lkm_hidden,interrupts_hook info");