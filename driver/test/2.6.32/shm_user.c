#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <netinet/in.h>

#define NLMSG_ALIGNTO	4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(64))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))

#define MAX_SIZE 2097152
#define DEVICE_FILENAME "/dev/smith"

typedef void (*rust_callback)(char *);

int shm_read_index = 8;
int pre_read_index = 0;
int shm_fd = -1;

struct msghdr msg;
const char *split_ymbol = "\n";
char user_id[16] = {0};
char shm_res[NLMSG_SPACE(4096)] = {0};
char *tmp_slot_len;
char *sh_mem;

struct msg_slot
{
    int len;
    int next;
};

struct sh_mem_list_head
{
    int read_index;
    int next;
};

struct msg_slot *slot;
struct sh_mem_list_head *list_head;

static char *get_user_id(const char *msg)
{
    int i;
    int first = strcspn(msg, split_ymbol);

    for (i = 0; i < sizeof(user_id); i++)
        user_id[i] = 0;

    for (i = 0; i < first; i++)
        user_id[i] = msg[i];

    return user_id;
}

static char *get_user(uid_t uid)
{
    struct passwd *pws;
    pws = getpwuid(uid);
    if (pws)
        return pws->pw_name;
    else
        return "UNKNOW";
}

struct msg_slot *get_slot(void)
{
    int i;
    for (i = 0; i < 9; i++)
        tmp_slot_len[i] = sh_mem[shm_read_index + i];

    return (struct msg_slot *)tmp_slot_len;
}

static void clear_sh_mem(void)
{
    int i;
    if (shm_read_index > 0 && pre_read_index > 0)
    {
        if (shm_read_index > pre_read_index) {
            for (i = 0; i < (shm_read_index - pre_read_index); i++)
                sh_mem[pre_read_index + i] = 0;
        } else {
            for (i = 0; i < (MAX_SIZE - pre_read_index); i++)
                sh_mem[pre_read_index + i] = 0;
        }
    }
}

static char *get_msg(struct msg_slot *slot)
{
    char *tmp_data;
    tmp_data = malloc(slot->len + 4);
    if (tmp_data) {
        memset(tmp_data, '\0', slot->len + 4);
        snprintf(tmp_data, slot->len + 1, "%s", &sh_mem[shm_read_index + 8]);
    }
    return tmp_data;
}

static char *shm_msg_factory_no_callback(char *msg)
{
    int shm_res_len;
    char *user_id = NULL;
    char *username = NULL;
    char time_buffer[16] = {0};
    struct timeval ts;
    memset(shm_res, 0, NLMSG_SPACE(4096));
    gettimeofday(&ts, NULL);
    sprintf(time_buffer, "%ld\0", ts.tv_sec * 1000 + ts.tv_usec / 1000);

    if (msg)
    {
        if(strlen(msg) < 4024) {
            strcat(shm_res, msg);
            free(msg);
            strcat(shm_res, "\n");
            shm_res_len = strlen(shm_res);

            if (shm_res_len > 16) {
                user_id = get_user_id(shm_res);
                username = get_user(atoi(user_id));
                strcat(shm_res, username);
                strcat(shm_res, "\n");
                strcat(shm_res, time_buffer);
                return shm_res;
            }
        } else {
            free(msg);
        }
    }
    return "";
}

void init(void)
{
    tmp_slot_len = malloc(8);
}

void shm_init(void)
{
    if (shm_fd == -1) {
        shm_read_index = 8;
        pre_read_index = 0;
        shm_fd = open(DEVICE_FILENAME, O_RDWR | O_SYNC);
        sh_mem = (char *)mmap(NULL, MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        list_head = (struct sh_mem_list_head *)mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        list_head->read_index = 0;
    }
}

void shm_close(void)
{
    if (shm_fd != -1) {
        close(shm_fd);
        munmap(sh_mem, MAX_SIZE);
        munmap(list_head, 8);
        shm_fd = -1;
    }
}

char *shm_run_no_callback(void)
{
    char *res = NULL;
    while (1) {
        slot = get_slot();
        if ((slot->next) == -1 || (slot->next) == 1) {
            if ((slot->len) > 0) {
                res = shm_msg_factory_no_callback(get_msg(slot));
                clear_sh_mem();
                list_head->read_index = shm_read_index;
                pre_read_index = shm_read_index;

                if (slot->next == 1)
                    shm_read_index = 8;
                else
                    shm_read_index = shm_read_index + 9 + slot->len;

                return res;
            }
        } else {
            nanosleep((const struct timespec[]){{0, 50000}}, NULL);
        }
    }
}

void main()
{
    init();
    shm_init();
    while (1)
        shm_run_no_callback();
}