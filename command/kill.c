#include "cmd_head.h"
int main(int argc, char *argv[]){
    if (argc < 2) {
        printf("Usage: kill <pid>\n");
        return 1;
    }
    int pid = atoi(argv[1]);
    // 简单保护：不允许 kill 系统任务 (0 ~ NR_TASKS-1)
    // 也不允许 kill 自己
    if (pid < NR_TASKS) {
        printf("Error: Cannot kill system task %d.\n", pid);
        return 1;
    }

    // 构造消息
    MESSAGE msg;
    msg.type = KILL_PROC;
    msg.PID = pid; // 将目标 PID 放入消息中

    // 发送给内存管理器
    send_recv(BOTH, TASK_MM, &msg);

    // 检查结果
    if (msg.RETVAL == 0) {
        printf("Process %d killed.\n", pid);
    } else {
        printf("Failed to kill process %d (PID not found or error).\n", pid);
    }

    return 0;
}