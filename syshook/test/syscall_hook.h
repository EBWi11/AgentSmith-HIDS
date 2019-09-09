/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2018
* File:		syscall_hook.h
* Description:	some struct for share memory
*******************************************************************/

/*
 ________________
| Reade Index    |
|................|
| Start Flag     |
|________________|
| Data Len       |
|................|
| Data           |
|________________|
| Data Len       |
|................|
| Data           |
|________________|
|       .        |
|       .        |
|       .        |
|________________|

Read Index: For AgentSmith-HIDS LKM check user space agent read stat,if too slow,LKM will stop
Start Flag: Jus for init
Data Len: Tell User Space Agent the Data Len
Data: LKM Hook Data

*/


struct msg_slot {
    int len;
    int next;
};

struct sh_mem_list_head {
    int read_index;
    int next;
};