/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2018
* File:		syscall_hook.h
* Description:	some struct for share memory
*******************************************************************/

struct msg_slot {
    int len;
    int next;
};

struct sh_mem_list_head {
    int read_index;
    int next;
};