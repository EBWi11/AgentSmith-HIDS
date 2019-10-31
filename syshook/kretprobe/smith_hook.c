/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2019
* File:		smith_hook.c
* Description:	hook sys_execve,sys_connect,sys_accept4,sys_ptrace,load_module,fsnotify,sys_recvfrom

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

#include "smith_hook.h"
#include <asm/syscall.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <linux/device.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/namei.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

#define DEVICE_NAME "smith"
#define CLASS_NAME "smith"
#define EXECVE_TYPE "59"
#define CONNECT_TYPE "42"
#define ACCEPT_TYPE "43"
#define INIT_MODULE_TYPE "175"
#define FINIT_MODULE_TYPE "313"
#define PTRACE_TYPE "101"
#define DNS_TYPE "601"
#define CREATE_FILE "602"

#define MAX_SIZE 2097152
#define CHECK_READ_INDEX_THRESHOLD 524288
#define CHECK_WRITE_INDEX_THRESHOLD 32768

#define EXIT_PROTECT 0

#define CONNECT_HOOK 1
#define ACCEPT_HOOK 1
#define EXECVE_HOOK 1
#define FSNOTIFY_HOOK 0
#define PTRACE_HOOK 1
#define RECVFROM_HOOK 1
#define LOAD_MODULE_HOOK 1

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])

char connect_kretprobe_state = 0x0;
char accept_kretprobe_state = 0x0;
char execve_kretprobe_state = 0x0;
char fsnotify_kretprobe_state = 0x0;
char ptrace_kretprobe_state = 0x0;
char recvfrom_kretprobe_state = 0x0;
char load_module_kretprobe_state = 0x0;

static int share_mem_flag = -1;
static int pre_slot_len = 0;
static int write_index = 8;
static struct class *class;
static struct device *device;
static int major;
static char *sh_mem = NULL;
static DEFINE_MUTEX(mchar_mutex);

static rwlock_t _write_index_lock;

struct connect_data {
    int fd;
};

struct accept_data {
    int fd;
};

struct execve_data {
    int fd;
};

struct recvfrom_data {
    int fd;
};

struct ptrace_data {
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

static inline void write_index_lock(void)
{
    write_lock(&_write_index_lock);
}

static inline void write_index_unlock(void)
{
    write_unlock(&_write_index_lock);
}

static void _init_share_mem(int type)
{
    struct sh_mem_list_head _init_list_head = {0, -1};
    if (type == 1)
        _init_list_head.next = 8;
    memcpy(sh_mem, &_init_list_head, 8);
}

static int device_open(struct inode *inode, struct file *file)
{
    if (!mutex_trylock(&mchar_mutex)) {
        return -1;
    } else {
        share_mem_flag = 1;
        write_index_lock();
        pre_slot_len = 0;
        write_index_unlock();
        write_index = 8;
        memset(sh_mem, '\0', MAX_SIZE);
        _init_share_mem(0);
    }
    return 0;
}

static int device_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret = 0;
    struct page *page = NULL;
    unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

    vma->vm_flags |= 0;

    if (size > MAX_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    page = virt_to_page((unsigned long)sh_mem + (vma->vm_pgoff << PAGE_SHIFT));
    ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size, vma->vm_page_prot);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

static int device_close(struct inode *indoe, struct file *file)
{
    mutex_unlock(&mchar_mutex);
    share_mem_flag = -1;
    return 0;
}

static const struct file_operations mchar_fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .mmap = device_mmap,
};

static int connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
    printk("connect --> %d\n", retval);
    return 0;
}

static int accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
    printk("accept --> %d\n", retval);
    return 0;
}

static int execve_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
    printk("execve --> %d\n", retval);
    return 0;
}

static int fsnotify_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	printk("fsnotify --> %d\n", retval);
	return 0;
}

static int ptrace_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	printk("ptrace --> %d\n", retval);
	return 0;
}

static int recvfrom_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	printk("recvfrom --> %d\n", retval);
	return 0;
}

static int load_module_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	printk("load_module --> %d\n", retval);
	return 0;
}

static struct kretprobe connect_kretprobe = {
	.handler		= connect_ret_handler,
	.data_size		= sizeof(struct connect_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe accept_kretprobe = {
	.handler		= accept_ret_handler,
	.data_size		= sizeof(struct accept_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe execve_kretprobe = {
	.handler		= execve_ret_handler,
	.data_size		= sizeof(struct execve_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe fsnotify_kretprobe = {
	.handler		= fsnotify_ret_handler,
	.data_size		= sizeof(struct fsnotify_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe ptrace_kretprobe = {
	.handler		= ptrace_ret_handler,
	.data_size		= sizeof(struct ptrace_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe recvfrom_kretprobe = {
	.handler		= recvfrom_ret_handler,
	.data_size		= sizeof(struct recvfrom_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe load_module_kretprobe = {
	.handler		= load_module_ret_handler,
	.data_size		= sizeof(struct load_module_data),
	.maxactive		= NR_CPUS,
};

static int connect_register_kretprobe(void)
{
	int ret;

	connect_kretprobe.kp.symbol_name = "sys_connect";
	ret = register_kretprobe(&connect_kretprobe);

	if (ret == 0)
        connect_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_connect(void)
{
	unregister_kretprobe(&connect_kretprobe);
}

static int accept_register_kretprobe(void)
{
	int ret;

	accept_kretprobe.kp.symbol_name = "sys_accept4";
	ret = register_kretprobe(&accept_kretprobe);

	if (ret == 0)
        accept_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_accept(void)
{
	unregister_kretprobe(&accept_kretprobe);
}

static int execve_register_kretprobe(void)
{
	int ret;

	execve_kretprobe.kp.symbol_name = "do_execve";
	ret = register_kretprobe(&execve_kretprobe);

	if (ret == 0)
        execve_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_execve(void)
{
	unregister_kretprobe(&execve_kretprobe);
}

static int fsnotify_register_kretprobe(void)
{
	int ret;

	fsnotify_kretprobe.kp.symbol_name = "fsnotify";
	ret = register_kretprobe(&fsnotify_kretprobe);

	if (ret == 0)
        fsnotify_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_fsnotify(void)
{
	unregister_kretprobe(&fsnotify_kretprobe);
}

static int ptrace_register_kretprobe(void)
{
	int ret;

	ptrace_kretprobe.kp.symbol_name = "sys_ptrace";
	ret = register_kretprobe(&ptrace_kretprobe);

	if (ret == 0)
        ptrace_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_ptrace(void)
{
	unregister_kretprobe(&ptrace_kretprobe);
}

static int recvfrom_register_kretprobe(void)
{
	int ret;

	recvfrom_kretprobe.kp.symbol_name = "sys_recvfrom";
	ret = register_kretprobe(&recvfrom_kretprobe);

	if (ret == 0)
        recvfrom_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_recvfrom(void)
{
	unregister_kretprobe(&recvfrom_kretprobe);
}

static int load_module_register_kretprobe(void)
{
	int ret;

	load_module_kretprobe.kp.symbol_name = "load_module";
	ret = register_kretprobe(&load_module_kretprobe);

	if (ret == 0)
        load_module_kretprobe_state = 0x1;

	return ret;
}

static void unregister_kretprobe_load_module(void)
{
	unregister_kretprobe(&load_module_kretprobe);
}

static int init_share_mem(void)
{
    int i;

    major = register_chrdev(0, DEVICE_NAME, &mchar_fops);

    if (major < 0) {
        pr_err("[SMITH] REGISTER_CHRDEV_ERROR\n");
        return -1;
    }

    class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(class)) {
        unregister_chrdev(major, DEVICE_NAME);
        pr_err("[SMITH] CLASS_CREATE_ERROR");
        return -1;
    }

    device = device_create(class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(device)) {
        class_destroy(class);
        unregister_chrdev(major, DEVICE_NAME);
        pr_err("[SMITH] DEVICE_CREATE_ERROR");
        return -1;
    }

    sh_mem = kzalloc(MAX_SIZE, GFP_KERNEL);

    if (sh_mem == NULL) {
        device_destroy(class, MKDEV(major, 0));
        class_destroy(class);
        unregister_chrdev(major, DEVICE_NAME);
        pr_err("[SMITH] SHMEM_INIT_ERROR\n");
        return -ENOMEM;
    }
    else {
        for (i = 0; i < MAX_SIZE; i += PAGE_SIZE)
            SetPageReserved(virt_to_page(((unsigned long)sh_mem) + i));
    }

    mutex_init(&mchar_mutex);
    return 0;
}

static void uninstall_share_mem(void)
{
    device_destroy(class, MKDEV(major, 0));
    class_unregister(class);
    class_destroy(class);
    unregister_chrdev(major, DEVICE_NAME);
}

static void uninstall_kretprobe(void)
{
    if (connect_kretprobe_state == 0x1)
	    unregister_kretprobe_connect();

	if (accept_kretprobe_state == 0x1)
	    unregister_kretprobe_accept();

    if (execve_kretprobe_state == 0x1)
	    unregister_kretprobe_execve();

    if (fsnotify_kretprobe_state == 0x1)
	    unregister_kretprobe_fsnotify();

    if (ptrace_kretprobe_state == 0x1)
	    unregister_kretprobe_ptrace();

    if (recvfrom_kretprobe_state == 0x1)
	    unregister_kretprobe_recvfrom();

    if (load_module_kretprobe_state == 0x1)
	    unregister_kretprobe_load_module();
}

static int __init smith_init(void)
{
	int ret;

    ret = init_share_mem();

    if (ret != 0)
        return ret;
    else
        printk(KERN_INFO "[SMITH] init_share_mem success \n");

    if (CONNECT_HOOK == 1) {
	    ret = connect_register_kretprobe();
	    if (ret < 0) {
		    printk(KERN_INFO "[SMITH] connect register_kretprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (ACCEPT_HOOK == 1) {
	ret = accept_register_kretprobe();
	    if (ret < 0) {
		    uninstall_kretprobe();
		    printk(KERN_INFO "[SMITH] accept register_kretprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (EXECVE_HOOK == 1) {
	ret = execve_register_kretprobe();
	    if (ret < 0) {
		    uninstall_kretprobe();
		    printk(KERN_INFO "[SMITH] execve register_kretprobe failed, returned %d\n", ret);
	    	return -1;
	    }
	}

    if (FSNOTIFY_HOOK == 1) {
	ret = fsnotify_register_kretprobe();
	    if (ret < 0) {
		    uninstall_kretprobe();
		    printk(KERN_INFO "[SMITH] fsnotify register_kretprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (PTRACE_HOOK == 1) {
	ret = ptrace_register_kretprobe();
	    if (ret < 0) {
		    uninstall_kretprobe();
		    printk(KERN_INFO "[SMITH] ptrace register_kretprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (RECVFROM_HOOK == 1) {
	ret = recvfrom_register_kretprobe();
	    if (ret < 0) {
		    uninstall_kretprobe();
		    printk(KERN_INFO "[SMITH] recvfrom register_kretprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

    if (LOAD_MODULE_HOOK == 1) {
	ret = load_module_register_kretprobe();
	    if (ret < 0) {
		    uninstall_kretprobe();
		    printk(KERN_INFO "[SMITH] load_module register_kretprobe failed, returned %d\n", ret);
		    return -1;
	    }
	}

#if (EXIT_PROTECT == 1)
    exit_protect_action()
#endif

	printk(KERN_INFO "[SMITH] register_kretprobe success: connect_hook: %d,accept_hook: %d,load_module_hook: %d,execve_hook: %d,fsnotify_hook: %d,ptrace_hook: %d,recvfrom_hook: %d\n",
	        CONNECT_HOOK, ACCEPT_HOOK, LOAD_MODULE_HOOK, EXECVE_HOOK, FSNOTIFY_HOOK, PTRACE_HOOK, RECVFROM_HOOK);

	return 0;
}

static void __exit smith_exit(void)
{
	uninstall_kretprobe();
	uninstall_share_mem();
	printk(KERN_INFO "[SMITH] uninstall_kretprobe success\n");
}

module_init(smith_init)
module_exit(smith_exit)

MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.0.1");
MODULE_AUTHOR("E_Bwill <cy_sniper@yeah.net>");
MODULE_DESCRIPTION("hook sys_execve,sys_connect,sys_accept4,sys_ptrace,load_module,fsnotify,sys_recvfrom");