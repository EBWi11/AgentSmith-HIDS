/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2018
* File:		smith_hook.h
* Description:	share memory
*******************************************************************/
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>

#define DEVICE_NAME "smith"
#define CLASS_NAME "smith"

#define MAX_SIZE 2097152
#define CHECK_READ_INDEX_THRESHOLD 524288
#define CHECK_WRITE_INDEX_THRESHOLD 32768

#define DELAY_TEST 0
#define KERNEL_PRINT 0

extern int share_mem_flag;

struct msg_slot {
    int len;
    int next;
};

struct sh_mem_list_head {
    int read_index;
    int next;
};

int init_share_mem(void);
int send_msg_to_user(char *msg, int kfree_flag);
void uninstall_share_mem(void);