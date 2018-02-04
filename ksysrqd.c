#include <linux/module.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/semaphore.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <linux/bio.h>
#include <net/sock.h>
#include <linux/string.h>

#define SYSRQD_PORT 4094
#define PASSWORD "skynet"
#define PROG_VERSION "0.2"
#define PROG_NAME "ksysrqd"
#define SYSRQDLOGINMSG "login: "

static struct task_struct *sysrqd_task;
static struct proc_dir_entry *proc_file;
static char skynet_password[32];
static char *sysrqd_options =
    "p)rint procs\n"
    "r)aw input\n"
    "e)terminate all\n"
    "i)kill everything left\n"
    "s)ync buffers\n"
    "u)nmount all disks\n"
    "b)oot system\n"
    "z)reisub\n# ";

struct sysrqd_network_t {
    struct socket *my_socket;
    struct socket *client_socket;
    struct sockaddr_in my_ipv4_addr;
    char *transmit;
} * sysrqd_network = NULL;

// Prototype
static int sysrqd_start_listening(void);
static void sysrqd_accept_handler(void);
static void sysrqd_manage_client(void);
static int sysrqd_send_message(char *message);
static int sysrqd_recv_message(char *, int len);
extern void handle_sysrq(int,struct tty_struct *);

/* Segment File Operations*/
static void *skynet_seq_start(struct seq_file *m, loff_t *index)
{
    static unsigned long counter = 0;

    if(*index == 0) {
        // Start von neuer Sequence
        return &counter;
    } else {
        *index = 0;
    }

    return 0;
}


static void skynet_seq_stop(struct seq_file *m, void *obj_ident)
{
    return;
}

static void *skynet_seq_next(struct seq_file *m, void *obj_ident, loff_t *index)
{
    unsigned long *v = (unsigned long * )obj_ident;
    (*v)++;
    (*index)++;
    return NULL;
}

static int skynet_seq_show(struct seq_file *m, void *obj_ident)
{
    unsigned long *v = (unsigned long*) obj_ident;
    seq_printf(m, "%d\n", (int )*v);
    return 0;
}

static ssize_t write_password (struct file *file, char const __user *buffer, size_t count, loff_t *data)
{
    int not_copied;
    char * kernel_buffer;
    char * temp_buffer;

    kernel_buffer = kmalloc(count, GFP_KERNEL);
    if( !kernel_buffer) {
        return -ENOMEM;
    }
    not_copied = copy_from_user(kernel_buffer, buffer, count);

    temp_buffer = kmalloc(count+1, GFP_KERNEL);
    if( !temp_buffer) {
        return -ENOMEM;
    }

    /* prepare temporary password */
    memset(temp_buffer,'\0', count+1);
    strncat(temp_buffer,kernel_buffer,count);
    strlcpy(skynet_password, temp_buffer, 32);

    kfree(kernel_buffer);
    return count-not_copied;
}

static struct seq_operations sops = {
    .start = skynet_seq_start,
    .next  = skynet_seq_next,
    .stop  = skynet_seq_stop,
    .show  = skynet_seq_show,
};

static int proc_open( struct inode *device, struct file *instance )
{
    return seq_open( instance, &sops );
}

static struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release,
    .write   = write_password
};

static int sysrqd_thread(void *data)
{
    /* Listen & Accept socket */
    sysrqd_start_listening();

    /* Accept handler */
    do {
        sysrqd_accept_handler();
    } while(!kthread_should_stop());

    if( sysrqd_network->my_socket != NULL)
        sock_release(sysrqd_network->my_socket);
    if( sysrqd_network->client_socket != NULL)
        sock_release(sysrqd_network->client_socket);

    sysrqd_network->my_socket = NULL;
    sysrqd_network->client_socket = NULL;
    return 0;
}

static void sysrqd_accept_handler()
{
    int err = 0, len, slen;
    struct sockaddr_in sin;

    err = kernel_accept(sysrqd_network->my_socket, &sysrqd_network->client_socket, 0);
    if( err < 0) {
        return ;
    }

    slen = sizeof(sin);
    err = kernel_getpeername(sysrqd_network->client_socket, (struct sockaddr *)&sin,  &slen );

    if( err < 0 ) {
        return ;
    }

    if( sysrqd_send_message(SYSRQDLOGINMSG) <= 0)  goto out;

    len = sysrqd_recv_message(sysrqd_network->transmit, strlen(skynet_password)+2);
    if(len == 0 || len < strlen(skynet_password)) {
        printk("Too small: %d\n", len);
        goto out;
    }

    if( strncmp(sysrqd_network->transmit,skynet_password,strlen(skynet_password)) != 0 ) {
        goto out;
    }

    sysrqd_manage_client();


out:
    if( sysrqd_network->client_socket != NULL) {
        sock_release(sysrqd_network->client_socket);
        sysrqd_network->client_socket = NULL;
    }

    return ;
}

static void sysrqd_manage_client()
{
    static int len;
    static char letter;
    static struct task_struct *p;

    len = sysrqd_send_message(sysrqd_options);
    if(len <= 0) return;

    memset(sysrqd_network->transmit,'\0', 256);
    len = sysrqd_recv_message(sysrqd_network->transmit, 1);

    if(len != 1) {
        return;
    }

    letter = *(sysrqd_network->transmit);

    if(letter == 'r' || letter == 'e' ||letter == 'i' ||letter == 's' ||letter == 'u' || letter == 'b') {
        handle_sysrq(letter,NULL);
        udelay(3000);
        goto manage_out;
    }

    if(letter == 'p') {
        for_each_process(p) {
            snprintf(sysrqd_network->transmit, 256, "[%d] [%s]\n", p->pid, p->comm);
            sysrqd_send_message(sysrqd_network->transmit);
        }
        goto manage_out;
    }

    if(letter == 'z') {
        handle_sysrq('r',NULL);
        udelay(10000);
        handle_sysrq('e',NULL);
        udelay(10000);
        handle_sysrq('i',NULL);
        udelay(10000);
        handle_sysrq('s',NULL);
        udelay(10000);
        handle_sysrq('u',NULL);
        udelay(10000);
        handle_sysrq('b',NULL);
        udelay(10000);
    }

manage_out:
    if( sysrqd_network->client_socket != NULL) {
        sock_release(sysrqd_network->client_socket);
        sysrqd_network->client_socket = NULL;
    }
    return;
}


static int sysrqd_send_message(char *message)
{
    int len;
    struct msghdr msg;
    struct kvec iov;

    iov.iov_base = (char *)message;
    iov.iov_len = strlen(message);

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    //msg.msg_iov = &iov;
    //msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = MSG_NOSIGNAL;

    len = kernel_sendmsg(sysrqd_network->client_socket, &msg, &iov, 1, iov.iov_len);

    udelay(3000);
    return len;
}

static int sysrqd_recv_message(char *message, int len)
{
    int ret;
    struct msghdr msg;
    struct kvec iov;

    iov.iov_base = (char *)message;
    iov.iov_len  = len;
    msg.msg_name = 0;
    msg.msg_namelen = 0;
    //msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ret = kernel_recvmsg(sysrqd_network->client_socket, &msg, &iov, 1, len, msg.msg_flags);
    if (signal_pending(current)) {
        printk("Interrupted by signal\n");
        return 0;
    }
    return ret;

}

static int sysrqd_start_listening(void)
{
    int ret = 0;

    /* Create socket */
    ret  = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sysrqd_network->my_socket);
    if(ret < 0 ) {
        printk("can't create sockets\n");
        return ret;
    }

    /* Reuse TCP */
    sysrqd_network->my_socket->sk->sk_reuse = 1;

    /* Fill structure */
    sysrqd_network->my_ipv4_addr.sin_port = htons(SYSRQD_PORT);
    sysrqd_network->my_ipv4_addr.sin_family = AF_INET;
    sysrqd_network->my_ipv4_addr.sin_addr.s_addr  = htonl(INADDR_ANY);

    /* Bind socket */
    ret = sysrqd_network->my_socket->ops->bind(sysrqd_network->my_socket,(struct sockaddr*)&sysrqd_network->my_ipv4_addr, sizeof(struct sockaddr));
    if(ret) {
        printk("can't bind socket\n");
        return ret;
    }

    /* Start Listener */
    ret = sysrqd_network->my_socket->ops->listen(sysrqd_network->my_socket, 32);
    if(ret < 0) {
        printk("can't listen on socket\n");
        return ret;
    }

    return ret;
}

static int __init sysrqd_init(void)
{
    printk("%s %s starting service on TCP port %d\n", PROG_NAME, PROG_VERSION, SYSRQD_PORT);

    sysrqd_network = kmalloc(sizeof(struct sysrqd_network_t), GFP_KERNEL);
    sysrqd_network->my_socket = NULL;
    sysrqd_network->client_socket = NULL;
    sysrqd_network->transmit = kmalloc(256, GFP_KERNEL);

    sysrqd_task = kthread_run(sysrqd_thread, NULL, "sysrqd");
    if (IS_ERR(sysrqd_task)) {
        printk("sysrqd: Failed create reader\n");
        sysrqd_task = NULL;
        return -EIO;
    }

    /* Copy standard passphrase */
    strlcpy(skynet_password, PASSWORD, strlen(PASSWORD)+1);

    proc_file = proc_create_data("ksysrqd", S_IRWXUGO, NULL, &fops, NULL);
    if (!proc_file)  {
        return -ENOMEM;
    }

    return 0;
}

static void __exit sysrqd_exit(void)
{

    if(sysrqd_task)
        force_sig(SIGKILL, sysrqd_task);

    if(sysrqd_task)
        kthread_stop(sysrqd_task);

    if(sysrqd_network) {
        kfree(sysrqd_network->transmit);
        kfree(sysrqd_network);
    }

    if(proc_file) {
        remove_proc_entry("ksysrqd", NULL);
    }

    printk("%s %s stopped service on TCP port %d\n", PROG_NAME, PROG_VERSION, SYSRQD_PORT);
    return;
}

module_init( sysrqd_init );
module_exit( sysrqd_exit );
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joerg Kost jk@ip-clear.de");
MODULE_DESCRIPTION("TCP Daemon, that allows to receive magic syskeys over tcpip\n");
