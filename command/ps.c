#include "cmd_head.h"
int main(int argc, char *argv[]){
	MESSAGE msg;
	struct proc p;
	printf("%3s %8s %6s %6s\n", "PID", "NAME", "STAT", "PPID");
	for (int i = 0; i < NR_TASKS + NR_PROCS; i++){
        // 防止数据残留，每次清零
        memset(&p, 0, sizeof(struct proc));
		msg.type = GET_PROC_INFO;
		msg.PID = i;
		msg.BUF = &p;
		send_recv(BOTH, TASK_SYS, &msg);

		if (p.p_flags != FREE_SLOT){
			// 打印NAME
			printf("%3d %8s ", i, p.name);
			// 打印STAT
			if (p.p_flags == SENDING||p.p_flags == RECEIVING
				||p.p_flags == WAITING||p.p_flags == HANGING){
				printf("%6d ",p.p_flags); 
			}else{ // 其他状态打印"-"
				printf("%6s ", "-");
			}
			// 打印父进程PID
			if (p.p_parent == NO_TASK){
				printf("%6s\n", "-");
			}else{
				printf("%6d\n", p.p_parent);
			}
		}
	}
}