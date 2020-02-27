/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2019
* File:		smith_hook.h
* Description:	smith_hook header
*******************************************************************/
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
#include <linux/fsnotify.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/tty.h>
#include <linux/mman.h>

#define SMITH_NAME_MAX	(PATH_MAX - sizeof(struct filename))

#define MPROTECT_TYPE "10"
#define EXECVE_TYPE "59"
#define CONNECT_TYPE "42"
#define PTRACE_TYPE "101"
#define DNS_TYPE "601"
#define CREATE_FILE "602"
#define LOAD_MODULE_TYPE "603"
#define UPDATE_CRED_TYPE "604"

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
  #define P_SYSCALL_LAYOUT_4_17
 #ifdef CONFIG_X86_64
  #define P_SYSCALL_PREFIX(x) P_TO_STRING(__x64_sys_ ## x)
    #define P_GET_IA32_COMPAT_SYSCALL_NAME(x) P_IA32_COMPAT_SYSCALL_PREFIX(x)
  #define P_IA32_COMPAT_SYSCALL_PREFIX(x) P_TO_STRING(__ia32_compat_sys_ ## x)
  #define P_COMPAT_SYSCALL_PREFIX(x) P_IA32_COMPAT_SYSCALL_PREFIX(x)
 #else
  #define P_SYSCALL_PREFIX(x) P_TO_STRING(sys_ ## x)
 #endif
#else
 #define P_SYSCALL_PREFIX(x) P_TO_STRING(sys_ ## x)
 #define P_COMPAT_SYSCALL_PREFIX(x) P_TO_STRING(compat_sys_ ## x)
#endif

#define P_TO_STRING(x) # x
#define P_GET_SYSCALL_NAME(x) P_SYSCALL_PREFIX(x)
#define P_GET_COMPAT_SYSCALL_NAME(x) P_COMPAT_SYSCALL_PREFIX(x)