/*
From: https://github.com/nbulischeck/tyton
Author: Nick Bulischeck <nbulisc@clemson.edu>
*/

#include "anti_rootkit.h"
#include "share_mem.h"

static int timeout = 15;
int (*ckt)(unsigned long addr) = NULL;
unsigned long *idt = NULL;
unsigned long *sct = NULL;
struct kset *mod_kset = NULL;

static void work_func(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(work, work_func);

#define BETWEEN_PTR(x, y, z) ( \
	((uintptr_t)x >= (uintptr_t)y) && \
	((uintptr_t)x < ((uintptr_t)y+(uintptr_t)z)) \
)

struct module *get_module_from_addr(unsigned long addr){
	return  __module_address(addr);
}

const char *find_hidden_module(unsigned long addr){
	const char *mod_name = NULL;
	struct kobject *cur, *tmp;
	struct module_kobject *kobj;

	list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry){
		if (!kobject_name(tmp))
			break;

		kobj = container_of(tmp, struct module_kobject, kobj);
		if (!kobj || !kobj->mod)
			continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		if (BETWEEN_PTR(addr, kobj->mod->core_layout.base, kobj->mod->core_layout.size)){
			mod_name = kobj->mod->name;
		}
#else
		if (BETWEEN_PTR(addr, kobj->mod->module_core, kobj->mod->core_size)){
			mod_name = kobj->mod->name;
		}
#endif
	}

	return mod_name;
}

void analyze_syscalls(void){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	int i;
	int syscall_number;
	const char *mod_name;
	unsigned long addr;
	struct module *mod;

	if (!sct)
		return;

	for (i = 0; i < NR_syscalls; i++){
		int flag = -1;
		addr = sct[i];
		if (!ckt(addr)){
			mutex_lock(&module_mutex);
			mod = get_module_from_addr(addr);
			if (mod){
			    mod_name = mod->name;
			    syscall_number = i;
			    flag = 0;
			} else {
				mod_name = find_hidden_module(addr);
				if (mod_name) {
                	syscall_number = i;
                	flag = 1;
				}
			}
			mutex_unlock(&module_mutex);
			if (flag != -1) {
			    char *result_str;
			    result_str = kzalloc(32 + strlen(mod_name), GFP_ATOMIC);
                snprintf(result_str, 32 + strlen(mod_name),
                         "%d%s%s%s%s%s%d%s%d",
                         -1, "\n", SYSCALL_HOOK, "\n", mod_name, "\n", flag, "\n", syscall_number);
                send_msg_to_user(result_str, 1);
			}
		}
	}
#endif
}

void analyze_interrupts(void){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	int i;
	int interrupt_number;
	const char *mod_name;
	unsigned long addr;
	struct module *mod;

	if (!idt || !ckt)
		return;

	for (i = 0; i < 256; i++){
		int flag = -1;
		addr = idt[i];
		if (!ckt(addr)){
			mutex_lock(&module_mutex);
			mod = get_module_from_addr(addr);
			if (mod){
			    interrupt_number = i;
			    mod_name = mod->name;
			    flag = 0;
			} else {
				mod_name = find_hidden_module(addr);
				if (mod_name) {
        			interrupt_number = i;
        		    flag = 1;
				}
			}
			mutex_unlock(&module_mutex);

			if (flag != -1) {
			    char *result_str;
                result_str = kzalloc(32 + strlen(mod_name), GFP_ATOMIC);
                snprintf(result_str, 32 + strlen(mod_name),
                         "%d%s%s%s%s%s%d%s%d",
                         -1, "\n", INTERRUPTS_HOOK, "\n", mod_name, "\n", flag, "\n", interrupt_number);
                send_msg_to_user(result_str, 1);
			}
		}
	}
#endif
}


void analyze_modules(void){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	char *result_str;
	struct kobject *cur, *tmp;
	struct module_kobject *kobj;

	list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry){
		if (!kobject_name(tmp))
			break;

		kobj = container_of(tmp, struct module_kobject, kobj);
		if (kobj && kobj->mod && kobj->mod->name){
			mutex_lock(&module_mutex);
			if(!find_module(kobj->mod->name)) {
                result_str =  kzalloc(32 + strlen(kobj->mod->name), GFP_ATOMIC);
                snprintf(result_str, 32 + strlen(kobj->mod->name),
                         "%s%s%s%s%s%s%s",
                         "-1", "\n", LKM_HIDDEN, "\n", kobj->mod->name, "\n", "1");
                send_msg_to_user(result_str, 1);
			}
			mutex_unlock(&module_mutex);
		}
	}
#endif
}

void analyze_fops(void){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	unsigned long addr;
	const char *mod_name;
	struct file *fp;
	struct module *mod;
    int flag = -1;
    char *result_str;

	fp = filp_open("/proc", O_RDONLY, S_IRUSR);
	if (IS_ERR(fp)){
		printk(KERN_INFO "[SMITH] open /proc error\n");
		return;
	}

	if (IS_ERR(fp->f_op)){
	    printk(KERN_INFO "[SMITH] /proc has no fops\n");
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	addr = (unsigned long)fp->f_op->iterate;
#else
	addr = (unsigned long)fp->f_op->readdir;
#endif

	if (!ckt(addr)){
		mutex_lock(&module_mutex);
		mod = get_module_from_addr(addr);
		if (mod){
		    mod_name = mod->name;
		    flag = 0;
		} else {
			mod_name = find_hidden_module(addr);
			if (mod_name){
		        mod_name = mod->name;
		        flag = 1;
			}
		}
		mutex_unlock(&module_mutex);
		if (flag != -1) {
            result_str = kzalloc(32 + strlen(mod_name), GFP_ATOMIC);
            snprintf(result_str, 32 + strlen(mod_name),
                     "%d%s%s%s%s%s%d",
                     -1, "\n", PROC_FILE_HOOK, "\n", mod_name, "\n", flag);
            send_msg_to_user(result_str, 1);
		}
	}
#endif
}

static void rootkit_check(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    analyze_fops();
    analyze_syscalls();
    analyze_modules();
    analyze_interrupts();
#endif
}

static void work_func(struct work_struct *dummy){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	rootkit_check();
	schedule_delayed_work(&work, round_jiffies_relative(timeout*60*HZ));
#endif
}

void init_del_workqueue(void)
{
	schedule_delayed_work(&work, 0);
}

void exit_del_workqueue(void)
{
	cancel_delayed_work_sync(&work);
}

void anti_rootkit_init()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	idt = (void *)kallsyms_lookup_name("idt_table");
	sct = (void *)kallsyms_lookup_name("sys_call_table");
	ckt = (void *)kallsyms_lookup_name("core_kernel_text");
	mod_kset = (void *)kallsyms_lookup_name("module_kset");
    init_del_workqueue();
#endif
}

void anti_root_kit_exit()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    exit_del_workqueue();
#endif
}