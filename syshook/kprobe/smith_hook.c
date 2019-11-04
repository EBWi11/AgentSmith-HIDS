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
#include "share_mem.h"
#include <asm/syscall.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/namei.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

#define EXECVE_TYPE "59"
#define CONNECT_TYPE "42"
#define ACCEPT_TYPE "43"
#define INIT_MODULE_TYPE "175"
#define FINIT_MODULE_TYPE "313"
#define PTRACE_TYPE "101"
#define DNS_TYPE "601"
#define CREATE_FILE "602"

#define EXIT_PROTECT 0

#define CONNECT_HOOK 1
#define ACCEPT_HOOK 1
#define EXECVE_HOOK 1
#define FSNOTIFY_HOOK 0
#define PTRACE_HOOK 1
#define RECVFROM_HOOK 1
#define LOAD_MODULE_HOOK 1

typedef unsigned short int uint16;
typedef unsigned long int uint32;

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

#define BigLittleSwap16(A) ((((uint16)(A)&0xff00) >> 8) | \
                           (((uint16)(A)&0x10ff) << 8))

int checkCPUendianRes = 0;
char connect_kprobe_state = 0x0;
char accept_kprobe_state = 0x0;
char execve_kprobe_state = 0x0;
char fsnotify_kprobe_state = 0x0;
char ptrace_kprobe_state = 0x0;
char recvfrom_kprobe_state = 0x0;
char load_module_kprobe_state = 0x0;

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

static void connect_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("connect---------------------------------\n", 0);
	}
}

static void accept_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("accept---------------------------------\n", 0);
	}
}

static void execve_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("execve---------------------------------\n", 0);
	}
}

static void fsnotify_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("fsnotify---------------------------------\n", 0);
	}
}

static void ptrace_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (share_mem_flag != -1) {
	    send_msg_to_user("ptrace---------------------------------\n", 0);
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
	if (share_mem_flag != -1) {
	    send_msg_to_user("load_module---------------------------------\n", 0);
	}
}

static struct kprobe connect_kprobe = {
    .symbol_name = "sys_connect",
	.post_handler = connect_post_handler,
};

static struct kprobe accept_kprobe = {
    .symbol_name = "sys_accept4",
	.post_handler = accept_post_handler,
};

static struct kprobe execve_kprobe = {
    .symbol_name = "do_execve",
	.post_handler = execve_post_handler,
};

static struct kprobe fsnotify_kprobe = {
    .symbol_name = "fsnotify",
	.post_handler = fsnotify_post_handler,
};

static struct kprobe ptrace_kprobe = {
    .symbol_name = "sys_ptrace",
	.post_handler = ptrace_post_handler,
};

static struct kprobe recvfrom_kprobe = {
    .symbol_name = "sys_recvfrom",
	.post_handler = recvfrom_post_handler,
};

static struct kprobe load_module_kprobe = {
    .symbol_name = "load_module",
	.post_handler = load_module_post_handler,
};

static int connect_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&connect_kprobe);

	if (ret == 0)
        connect_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_connect(void)
{
	unregister_kprobe(&connect_kprobe);
}

static int accept_register_kprobe(void)
{
	int ret;
	ret = register_kprobe(&accept_kprobe);

	if (ret == 0)
        accept_kprobe_state = 0x1;

	return ret;
}

static void unregister_kprobe_accept(void)
{
	unregister_kprobe(&accept_kprobe);
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
	    unregister_kprobe_connect();

	if (accept_kprobe_state == 0x1)
	    unregister_kprobe_accept();

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

    if (ACCEPT_HOOK == 1) {
	ret = accept_register_kprobe();
	    if (ret < 0) {
		    uninstall_kprobe();
		    uninstall_share_mem();
		    printk(KERN_INFO "[SMITH] accept register_kprobe failed, returned %d\n", ret);
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

	printk(KERN_INFO "[SMITH] register_kprobe success: connect_hook: %d,accept_hook: %d,load_module_hook: %d,execve_hook: %d,fsnotify_hook: %d,ptrace_hook: %d,recvfrom_hook: %d\n",
	        CONNECT_HOOK, ACCEPT_HOOK, LOAD_MODULE_HOOK, EXECVE_HOOK, FSNOTIFY_HOOK, PTRACE_HOOK, RECVFROM_HOOK);

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
MODULE_DESCRIPTION("hook sys_execve,sys_connect,sys_accept4,sys_ptrace,load_module,fsnotify,sys_recvfrom");