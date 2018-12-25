#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 10240

int sock_fd;
FILE *fp_out;
struct msghdr msg;
struct iovec iov;
struct nlmsghdr *nlh = NULL;
struct sockaddr_nl src_addr, dest_addr;
struct timespec time_start = {0, 0}, time_end = {0, 0};
const char *split_ymbol = "\n";
char user_id[16] = {0};
char netlink_res[NLMSG_SPACE(MAX_PAYLOAD)] = {0};

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

static int nids_agent_run(void)
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh), "NIDS_AGENT_UP");
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sock_fd, &msg, 0);
    return 1;
}

static int nids_agent_close(void)
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh), "NIDS_AGENT_DOWN");
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sock_fd, &msg, 0);
    return 1;
}

static int close_sock(void)
{
    return close(sock_fd);
}

static char *get_user(uid_t uid)
{
    struct passwd *pws;
    pws = getpwuid(uid);
    if (pws)
        return pws->pw_name;
    else
        return "ERROR";
}

static char *get_recvmsg(void)
{
    char *res = NULL;
    char *tmp_res = NULL;
    char *user_id = NULL;
    char *username = NULL;
    memset(netlink_res, 0, NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    recvmsg(sock_fd, &msg, 0);
    tmp_res = NLMSG_DATA(nlh);
    strcat(netlink_res, tmp_res);

    if (strlen(netlink_res) > 12)
    {
        strcat(netlink_res, "\n");
        user_id = get_user_id(netlink_res);
        username = get_user(atoi(user_id));
        strcat(netlink_res, username);
        return netlink_res;
    }

    return netlink_res;
}

int main()
{
    char *res = NULL;

    if (nids_agent_run() == 1)
    {
        while (1)
        {
            res = get_recvmsg();
            if(res){
                 printf("%s\n",res);
            }
        }
        close_sock();
    }
    fclose(fp_out);
}