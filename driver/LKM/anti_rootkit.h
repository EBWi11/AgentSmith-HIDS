#include <asm/asm-offsets.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/kernel.h>

void anti_rootkit_init(void);
void anti_root_kit_exit(void);

#define PROC_FILE_HOOK "700"
#define SYSCALL_HOOK "701"
#define LKM_HIDDEN "702"
#define INTERRUPTS_HOOK "703"