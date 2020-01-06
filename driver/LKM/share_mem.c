/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2019
* File:		smith_hook.c
* Description:	share memory
*******************************************************************/
#include "share_mem.h"

static DEFINE_MUTEX(mchar_mutex);
static char *list_head_char;
static int check_read_index_flag = -1;
static int pre_slot_len = 0;
static int write_index = 8;
static struct class *class;
static struct device *device;
static int major;
static char *sh_mem = NULL;
static rwlock_t _write_index_lock;

static void lock_init(void);
static inline void write_index_lock(void);
static inline void write_index_unlock(void);
static void do_init_share_mem(int type);
static int device_open(struct inode *inode, struct file *file);
static int device_close(struct inode *indoe, struct file *file);
static int device_mmap(struct file *filp, struct vm_area_struct *vma);

static const struct file_operations mchar_fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .mmap = device_mmap,
};

static int get_read_index(void);
static struct msg_slot get_solt(int len, int next);
static int get_write_index(void);
static void fix_write_index(int index);
static int send_msg_to_user_memshare(char *msg, int kfree_flag);

static void lock_init(void)
{
    rwlock_init(&_write_index_lock);
}

static inline void write_index_lock(void)
{
    write_lock(&_write_index_lock);
}

static inline void write_index_unlock(void)
{
    write_unlock(&_write_index_lock);
}

static void do_init_share_mem(int type)
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
        do_init_share_mem(0);
    }
    return 0;
}

static int device_close(struct inode *indoe, struct file *file)
{
    mutex_unlock(&mchar_mutex);
    share_mem_flag = -1;

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

static int get_read_index(void)
{
    int i;
    struct sh_mem_list_head *_list_head;

    for (i = 0; i < 8; i++)
        list_head_char[i] = sh_mem[i];

    _list_head = (struct sh_mem_list_head *)list_head_char;
    return _list_head->read_index;
}

static struct msg_slot get_solt(int len, int next)
{
    struct msg_slot new_msg_slot = {len, next};
    return new_msg_slot;
}

static int get_write_index(void)
{
    return write_index;
}

static void fix_write_index(int index)
{
    write_index = index;
}

static int send_msg_to_user_memshare(char *msg, int kfree_flag)
{
    int raw_data_len = 0;
    int curr_write_index = -1;
    int now_write_index = -1;
    int now_read_index = -1;
    struct msg_slot new_msg_slot;

    if(likely(share_mem_flag == 1)) {
        raw_data_len = strlen(msg);

        if(unlikely(raw_data_len == 0)) {
            if (msg && kfree_flag == 1)
                kfree(msg);
            return 0;
        }

        write_index_lock();

        curr_write_index = get_write_index();

        if(unlikely(pre_slot_len != 0))
            now_write_index = curr_write_index + 1;
        else
            now_write_index = curr_write_index;

        if(unlikely(check_read_index_flag == 1)) {
            now_read_index = get_read_index();
            if (now_read_index > curr_write_index + 1) {
                if ((curr_write_index + 1024 + raw_data_len) > now_read_index)
                    goto out;
            }
        }

        if(unlikely((curr_write_index + raw_data_len) >= BOUNDARY)) {
            now_read_index = get_read_index();
            if (now_read_index <= CHECK_READ_INDEX_THRESHOLD) {
#if (KERNEL_PRINT == 1)
                printk("READ IS TOO SLOW!! READ_INDEX:%d\n", now_read_index);
#endif
                check_read_index_flag = 1;
            } else
                check_read_index_flag = -1;

            new_msg_slot = get_solt(raw_data_len, 1);
            memcpy(&sh_mem[now_write_index], &new_msg_slot, 8);
            memcpy(&sh_mem[now_write_index + 8], msg, raw_data_len);
            fix_write_index(7);

#if (KERNEL_PRINT == 1)
            printk("curr_write_index:%d pre_slot_len:%d now_write_index:%d now_read_index:%d\n",
                   curr_write_index, pre_slot_len, now_write_index, now_read_index);
#endif
        } else {
            new_msg_slot = get_solt(raw_data_len, -1);
            memcpy(&sh_mem[now_write_index], &new_msg_slot, 8);
            memcpy(&sh_mem[now_write_index + 8], msg, raw_data_len);
            fix_write_index(now_write_index + 8 + raw_data_len);
        }

        pre_slot_len = raw_data_len + 8;
        write_index_unlock();
    }

    if(likely(msg && kfree_flag == 1))
        kfree(msg);

    return 0;

out:
    write_index_unlock();
    if(likely(msg && kfree_flag == 1))
        kfree(msg);

    return 0;
}

int send_msg_to_user(char *msg, int kfree_flag)
{
#if (KERNEL_PRINT == 2)
    printk("%s\n", msg);
#endif
    return send_msg_to_user_memshare(msg, kfree_flag);
}

int init_share_mem(void)
{
    int i;
    share_mem_flag = -1;
    list_head_char = kzalloc(8, GFP_ATOMIC);
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
    } else {
        for (i = 0; i < MAX_SIZE; i += PAGE_SIZE)
            SetPageReserved(virt_to_page(((unsigned long)sh_mem) + i));
    }

    mutex_init(&mchar_mutex);
    lock_init();
    return 0;
}

void uninstall_share_mem(void)
{
    int i;
    device_destroy(class, MKDEV(major, 0));
    class_unregister(class);
    class_destroy(class);
    unregister_chrdev(major, DEVICE_NAME);

    if (list_head_char)
        kfree(list_head_char);

    if (sh_mem) {
        for (i = 0; i < MAX_SIZE; i += PAGE_SIZE)
            ClearPageReserved(virt_to_page(((unsigned long)sh_mem) + i));
        kfree(sh_mem);
    }
}