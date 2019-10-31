#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/inet_sock.h>

struct my_data {
    int fd;
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
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe accept_kretprobe = {
	.handler		= accept_ret_handler,
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe execve_kretprobe = {
	.handler		= execve_ret_handler,
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe fsnotify_kretprobe = {
	.handler		= fsnotify_ret_handler,
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe ptrace_kretprobe = {
	.handler		= ptrace_ret_handler,
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe recvfrom_kretprobe = {
	.handler		= recvfrom_ret_handler,
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static struct kretprobe load_module_kretprobe = {
	.handler		= load_module_ret_handler,
	.data_size		= sizeof(struct my_data),
	.maxactive		= NR_CPUS,
};

static int connect_hook(void)
{
	int ret;

	connect_kretprobe.kp.symbol_name = "sys_connect";
	ret = register_kretprobe(&connect_kretprobe);

	return ret;
}

static void unregister_kretprobe_connect(void)
{
	unregister_kretprobe(&connect_kretprobe);
}

static int accept_hook(void)
{
	int ret;

	accept_kretprobe.kp.symbol_name = "sys_accept4";
	ret = register_kretprobe(&accept_kretprobe);

	return ret;
}

static void unregister_kretprobe_accept(void)
{
	unregister_kretprobe(&accept_kretprobe);
}

static int execve_hook(void)
{
	int ret;

	execve_kretprobe.kp.symbol_name = "do_execve";
	ret = register_kretprobe(&execve_kretprobe);

	return ret;
}

static void unregister_kretprobe_execve(void)
{
	unregister_kretprobe(&execve_kretprobe);
}

static int fsnotify_hook(void)
{
	int ret;

	fsnotify_kretprobe.kp.symbol_name = "fsnotify";
	ret = register_kretprobe(&fsnotify_kretprobe);

	return ret;
}

static void unregister_kretprobe_fsnotify(void)
{
	unregister_kretprobe(&fsnotify_kretprobe);
}

static int ptrace_hook(void)
{
	int ret;

	ptrace_kretprobe.kp.symbol_name = "sys_ptrace";
	ret = register_kretprobe(&ptrace_kretprobe);

	return ret;
}

static void unregister_kretprobe_ptrace(void)
{
	unregister_kretprobe(&ptrace_kretprobe);
}

static int recvfrom_hook(void)
{
	int ret;

	recvfrom_kretprobe.kp.symbol_name = "sys_recvfrom";
	ret = register_kretprobe(&recvfrom_kretprobe);

	return ret;
}

static void unregister_kretprobe_recvfrom(void)
{
	unregister_kretprobe(&recvfrom_kretprobe);
}

static int load_module_hook(void)
{
	int ret;

	load_module_kretprobe.kp.symbol_name = "load_module";
	ret = register_kretprobe(&load_module_kretprobe);

	return ret;
}

static void unregister_kretprobe_load_module(void)
{
	unregister_kretprobe(&load_module_kretprobe);
}

static int __init kretprobe_init(void)
{
	int ret;

	ret = connect_hook();
	if (ret < 0) {
		printk(KERN_INFO "connect register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	ret = accept_hook();
	if (ret < 0) {
		unregister_kretprobe_connect();
		printk(KERN_INFO "accept register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	ret = execve_hook();
	if (ret < 0) {
		unregister_kretprobe_connect();
		unregister_kretprobe_accept();
		printk(KERN_INFO "execve register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	ret = fsnotify_hook();
	if (ret < 0) {
		unregister_kretprobe_connect();
		unregister_kretprobe_accept();
		unregister_kretprobe_execve();
		printk(KERN_INFO "execve register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	ret = ptrace_hook();
	if (ret < 0) {
		unregister_kretprobe_connect();
		unregister_kretprobe_accept();
		unregister_kretprobe_execve();
		//unregister_kretprobe_fsnotify();
		printk(KERN_INFO "execve register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	ret = recvfrom_hook();
	if (ret < 0) {
		unregister_kretprobe_connect();
		unregister_kretprobe_accept();
		unregister_kretprobe_execve();
		unregister_kretprobe_fsnotify();
		unregister_kretprobe_ptrace();
		printk(KERN_INFO "execve register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	ret = load_module_hook();
	if (ret < 0) {
		unregister_kretprobe_connect();
		unregister_kretprobe_accept();
		unregister_kretprobe_execve();
		unregister_kretprobe_fsnotify();
		unregister_kretprobe_ptrace();
		unregister_kretprobe_recvfrom();
		printk(KERN_INFO "execve register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe_connect();
	unregister_kretprobe_accept();
	unregister_kretprobe_execve();
	unregister_kretprobe_fsnotify();
	unregister_kretprobe_ptrace();
	unregister_kretprobe_recvfrom();
	unregister_kretprobe_load_module();
	printk(KERN_INFO "-- REMOVE SMITH --\n");
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
