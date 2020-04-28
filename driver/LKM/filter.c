/*******************************************************************
* Project:	AgentSmith-HIDS
* Author:	E_BWill
* Year:		2020
* File:		filter.c
* Description:	smith filter
*******************************************************************/

#include "filter.h"

static struct class *filter_class;
static struct device *filter_device;
static int filter_major;
static char *sh_mem = NULL;

struct rb_root execve_exe_whitelist = RB_ROOT;
struct rb_root connect_dip_whitelist = RB_ROOT;

static rwlock_t __write_lock;

static void lock_init(void);

static inline void _write_lock(void);

static inline void _write_unlock(void);

static inline void _read_lock(void);

static inline void _read_unlock(void);

static int device_mmap(struct file *filp, struct vm_area_struct *vma);

static ssize_t device_write(struct file *filp, const __user char *buff, size_t len, loff_t *off);

static const struct file_operations mchar_fops = {
        .owner = THIS_MODULE,
        .mmap = device_mmap,
        .write = device_write,
};

static void lock_init(void) {
    rwlock_init(&__write_lock);
}

static inline void _write_lock(void) {
    write_lock(&__write_lock);
}

static inline void _write_unlock(void) {
    write_unlock(&__write_lock);
}

static inline void _read_lock(void) {
    read_lock(&__write_lock);
}

static inline void _read_unlock(void) {
    read_unlock(&__write_lock);
}

struct whitelist_node {
    struct rb_node node;
    char *data;
};

int exist_rb(struct rb_root *root, char *string) {
    struct rb_node *node = root->rb_node;

    while (node) {
        struct whitelist_node *data = container_of(node, struct whitelist_node, node);
        int result;

        result = strcmp(string, data->data);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return 1;
    }
    return 0;
}

struct whitelist_node *search_rb(struct rb_root *root, char *string)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct whitelist_node *data = container_of(node, struct whitelist_node, node);
        int result;

        result = strcmp(string, data->data);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

int insert_rb(struct rb_root *root, struct whitelist_node *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct whitelist_node *this = container_of(*new, struct whitelist_node, node);
        int res;

        res = strcmp(data->data, this->data);

        parent = *new;
        if (res < 0)
            new = &((*new)->rb_left);
        else if (res > 0)
            new = &((*new)->rb_right);
        else
            return -1;
    }

    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 0;
}

void del_rb(struct rb_root *root, char *data) {
    struct whitelist_node *node;
    if(!data)
        return;
    if ((node = search_rb(root, data)) == NULL)
        return;
    rb_erase(&node->node, root);
    kfree(node);
}

void del_rb_by_data(struct rb_root *root, char *data) {
    struct whitelist_node *node;
    if(!data)
        return;
    if ((node = search_rb(root, data)) == NULL)
        return;
    rb_erase(&node->node, root);
    kfree(node->data);
    kfree(node);
}

static void add_execve_exe_whitelist(char *data) {
    struct whitelist_node *node;
    if(!data)
        return;
    
    node = kzalloc(sizeof(struct whitelist_node), GFP_ATOMIC);
    if (!node)
        return;
    
    node->data = data;
    insert_rb(&execve_exe_whitelist, node);
}

static void del_execve_exe_whitelist(char *data) {
    del_rb_by_data(&execve_exe_whitelist, data);
}

static void del_all_execve_exe_whitelist(void) {
    struct rb_node *node;
    for (node = rb_first(&execve_exe_whitelist); node; node = rb_next(node)) {
        rb_erase(node, &execve_exe_whitelist);
        kfree(node);
    }
}

int execve_exe_check(char *data) {
    if(likely(data))
        return exist_rb(&execve_exe_whitelist, data);
    else
        return 0;
}

static void add_connect_dip_whitelist(char *data) {
    struct whitelist_node *node;
    node = kzalloc(sizeof(struct whitelist_node), GFP_ATOMIC);
    if (!node)
        return;
    node->data = data;
    insert_rb(&connect_dip_whitelist, node);
}

static void del_connect_dip_whitelist(char *data) {
    del_rb_by_data(&connect_dip_whitelist, data);
}

static void del_all_connect_dip_whitelist(void) {
    struct rb_node *node;
    for (node = rb_first(&connect_dip_whitelist); node; node = rb_next(node)) {
        rb_erase(node, &connect_dip_whitelist);
        kfree(node);
    }
}

int connect_dip_check(char *data) {
    if(likely(data))
        return exist_rb(&connect_dip_whitelist, data);
    else
        return 0;
}

static ssize_t device_write(struct file *filp, const __user char *buff, size_t len, loff_t *off) {
    int res;
    char flag = '`';
    char *data_main;

    get_user(flag, buff);

    if (len < 3)
        return len;

    data_main = kzalloc(len, GFP_ATOMIC);
    if(!data_main)
        return len;

    if(copy_from_user(data_main, buff+1, len))
        return len;

    switch (flag) {
        case 49:
            _write_lock();
            add_execve_exe_whitelist(strim(data_main));
            _write_unlock();
            break;
        case 50:
            _write_lock();
            del_execve_exe_whitelist(strim(data_main));
            _write_unlock();
            break;
        case 51:
            _write_lock();
            del_all_execve_exe_whitelist();
            _write_unlock();
            break;
        case 52:
            _write_lock();
            add_connect_dip_whitelist(strim(data_main));
            _write_unlock();
            break;
        case 53:
            _write_lock();
            del_connect_dip_whitelist(strim(data_main));
            _write_unlock();
            break;
        case 54:
            _write_lock();
            del_all_connect_dip_whitelist();
            _write_unlock();
            break;
        case 55:
            res = execve_exe_check(strim(data_main));
            printk("[SMITH DEBUG] execve_exe_check:%s %d", strim(data_main), res);
            break;
        case 56:
            res = connect_dip_check(strim(data_main));
            printk("[SMITH DEBUG] connect_dip_check:%s %d", strim(data_main), res);
            break;
    }

    return len;
}

static int device_mmap(struct file *filp, struct vm_area_struct *vma) {
    int ret = 0;
    struct page *page = NULL;
    unsigned long size = (unsigned long) (vma->vm_end - vma->vm_start);

    vma->vm_flags |= 0;

    if (size > SINGLE_MAX_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    page = virt_to_page((unsigned long) sh_mem + (vma->vm_pgoff << PAGE_SHIFT));
    ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size, vma->vm_page_prot);
    if (ret != 0) {
        goto out;
    }

    out:
    return ret;
}

int init_filter(void) {
    int i;
    filter_major = register_chrdev(0, FILTER_DEVICE_NAME, &mchar_fops);

    if (filter_major < 0) {
        pr_err("[SMITH FILTER] REGISTER_CHRDEV_ERROR\n");
        return -1;
    }

    filter_class = class_create(THIS_MODULE, FILTER_CLASS_NAME);
    if (IS_ERR(filter_class)) {
        unregister_chrdev(filter_major, FILTER_DEVICE_NAME);
        pr_err("[SMITH FILTER] CLASS_CREATE_ERROR");
        return -1;
    }

    filter_device = device_create(filter_class, NULL, MKDEV(filter_major, 0), NULL, FILTER_DEVICE_NAME);
    if (IS_ERR(filter_device)) {
        class_destroy(filter_class);
        unregister_chrdev(filter_major, FILTER_DEVICE_NAME);
        pr_err("[SMITH FILTER] DEVICE_CREATE_ERROR");
        return -1;
    }

    sh_mem = kzalloc(SINGLE_MAX_SIZE, GFP_ATOMIC);

    if (sh_mem == NULL) {
        device_destroy(filter_class, MKDEV(filter_major, 0));
        class_destroy(filter_class);
        unregister_chrdev(filter_major, FILTER_DEVICE_NAME);
        pr_err("[SMITH FILTER] SHMEM_INIT_ERROR\n");
        return -ENOMEM;
    } else {
        for (i = 0; i < SINGLE_MAX_SIZE; i += PAGE_SIZE)
            SetPageReserved(virt_to_page(((unsigned long) sh_mem) + i));
    }

    lock_init();
    return 0;
}

void uninstall_filter(void) {
    device_destroy(filter_class, MKDEV(filter_major, 0));
    class_unregister(filter_class);
    class_destroy(filter_class);
    del_all_execve_exe_whitelist();
    del_all_connect_dip_whitelist();
    unregister_chrdev(filter_major, FILTER_DEVICE_NAME);
}