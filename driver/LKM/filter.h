/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2020
* File:		filter.h
* Description:	smith filter
*******************************************************************/
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/rbtree.h>

#define FILTER_DEVICE_NAME "control_smith"
#define FILTER_CLASS_NAME "control_smith"

#define SINGLE_MAX_SIZE 8192

int init_filter(void);
void uninstall_filter(void);

int execve_exe_check(char *data);
int connect_dip_check(char *data);