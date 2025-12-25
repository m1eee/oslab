
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                            main.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                    Forrest Yu, 2005
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"


/*****************************************************************************
 *                               kernel_main
 *****************************************************************************/
/**
 * jmp from kernel.asm::_start. 
 * 
 *****************************************************************************/
PUBLIC int kernel_main()
{
	disp_str("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

	int i, j, eflags, prio;
        u8  rpl;
        u8  priv; /* privilege */

	struct task * t;
	struct proc * p = proc_table;

	char * stk = task_stack + STACK_SIZE_TOTAL;

	for (i = 0; i < NR_TASKS + NR_PROCS; i++,p++,t++) {
		if (i >= NR_TASKS + NR_NATIVE_PROCS) {
			p->p_flags = FREE_SLOT;
			continue;
		}

	        if (i < NR_TASKS) {     /* TASK */
                        t	= task_table + i;
                        priv	= PRIVILEGE_TASK;
                        rpl     = RPL_TASK;
                        eflags  = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */
			prio    = 15;
                }
                else {                  /* USER PROC */
                        t	= user_proc_table + (i - NR_TASKS);
                        priv	= PRIVILEGE_USER;
                        rpl     = RPL_USER;
                        eflags  = 0x202;	/* IF=1, bit 2 is always 1 */
			prio    = 5;
                }

		strcpy(p->name, t->name);	/* name of the process */
		p->p_parent = NO_TASK;

		if (strcmp(t->name, "INIT") != 0) {
			p->ldts[INDEX_LDT_C]  = gdt[SELECTOR_KERNEL_CS >> 3];
			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];

			/* change the DPLs */
			p->ldts[INDEX_LDT_C].attr1  = DA_C   | priv << 5;
			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;
		}
		else {		/* INIT process */
			unsigned int k_base;
			unsigned int k_limit;
			int ret = get_kernel_map(&k_base, &k_limit);
			assert(ret == 0);
			init_desc(&p->ldts[INDEX_LDT_C],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_C | priv << 5);

			init_desc(&p->ldts[INDEX_LDT_RW],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);
		}

		p->regs.cs = INDEX_LDT_C << 3 |	SA_TIL | rpl;
		p->regs.ds =
			p->regs.es =
			p->regs.fs =
			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;
		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;
		p->regs.eip	= (u32)t->initial_eip;
		p->regs.esp	= (u32)stk;
		p->regs.eflags	= eflags;

		p->ticks = p->priority = prio;

		p->p_flags = 0;
		p->p_msg = 0;
		p->p_recvfrom = NO_TASK;
		p->p_sendto = NO_TASK;
		p->has_int_msg = 0;
		p->q_sending = 0;
		p->next_sending = 0;

		for (j = 0; j < NR_FILES; j++)
			p->filp[j] = 0;

		stk -= t->stacksize;
	}

	k_reenter = 0;
	ticks = 0;

	p_proc_ready	= proc_table;

	init_clock();
        init_keyboard();

	restart();

	while(1){}
}


/*****************************************************************************
 *                                get_ticks
 *****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
 * @struct posix_tar_header
 * Borrowed from GNU `tar'
 */
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
	/* 500 */
};

/*****************************************************************************
 *                                untar
 *****************************************************************************/
/**
 * Extract the tar file and store them.
 * 
 * @param filename The tar file.
 *****************************************************************************/
void untar(const char * filename)
{
	printf("{UNTAR} ========== Extracting command archive ==========\n");
	printf("{UNTAR} Opening archive: %s\n", filename);
	
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);
	int i = 0;
	int bytes = 0;

	while (1) {
		bytes = read(fd, buf, SECTOR_SIZE);
		assert(bytes == SECTOR_SIZE); /* size of a TAR file
					       * must be multiple of 512
					       */
		if (buf[0] == 0) {
			if (i == 0)
				printf("{UNTAR} Archive is empty or already extracted.\n");
			break;
		}
		i++;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR | O_TRUNC);
		if (fdout == -1) {
			printf("{UNTAR} [ERROR] Failed to extract: %s\n", phdr->name);
			printf("{UNTAR} Extraction aborted!\n");
			close(fd);
			return;
		}
		printf("{UNTAR} [EXTRACT] %s (size=%d bytes)\n", phdr->name, f_len);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
			     ((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			bytes = write(fdout, buf, iobytes);
			assert(bytes == iobytes);
			bytes_left -= iobytes;
		}
		close(fdout);
	}

	if (i) {
		lseek(fd, 0, SEEK_SET);
		buf[0] = 0;
		bytes = write(fd, buf, 1);
		assert(bytes == 1);
	}

	close(fd);

	printf("{UNTAR} ========== Extraction complete: %d files ==========\n", i);
}

/*===========================================================================*
 *                    Shell 层完整性校验模块                                   *
 *===========================================================================*/

/* 最大可信程序数量和程序名长度 */
#define MAX_TRUSTED_PROGS  16
#define MAX_PROG_NAME      16

/* 可信程序条目 */
struct trusted_prog {
	char name[MAX_PROG_NAME];
	unsigned int crc32;
	int valid;
};

/* 可信程序表 (静态存储) */
PRIVATE struct trusted_prog trusted_progs[MAX_TRUSTED_PROGS];
PRIVATE int trusted_table_init = 0;

/**
 * 简化的 CRC32 计算 (查表法)
 */
PRIVATE unsigned int crc32_table[256];
PRIVATE int crc32_table_init = 0;

PRIVATE void init_crc32_table()
{
	unsigned int i, j, crc;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc = crc >> 1;
		}
		crc32_table[i] = crc;
	}
	crc32_table_init = 1;
}

PRIVATE unsigned int calc_crc32(const char *data, int len)
{
	unsigned int crc = 0xFFFFFFFF;
	int i;
	if (!crc32_table_init) init_crc32_table();
	for (i = 0; i < len; i++) {
		crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
	}
	return crc ^ 0xFFFFFFFF;
}

/**
 * 初始化可信程序表
 */
PRIVATE void init_trusted_table()
{
	int i;
	for (i = 0; i < MAX_TRUSTED_PROGS; i++) {
		trusted_progs[i].valid = 0;
	}
	trusted_table_init = 1;
}

/**
 * 查找可信程序
 */
PRIVATE int find_trusted_prog(const char *name)
{
	int i;
	for (i = 0; i < MAX_TRUSTED_PROGS; i++) {
		if (trusted_progs[i].valid && strcmp(trusted_progs[i].name, name) == 0)
			return i;
	}
	return -1;
}

/**
 * 添加可信程序
 */
PRIVATE int add_trusted_prog(const char *name, unsigned int crc32)
{
	int i;
	for (i = 0; i < MAX_TRUSTED_PROGS; i++) {
		if (!trusted_progs[i].valid) {
			strcpy(trusted_progs[i].name, name);
			trusted_progs[i].crc32 = crc32;
			trusted_progs[i].valid = 1;
			return 0;
		}
	}
	return -1;
}

/**
 * Shell 层完整性校验函数
 * 在 execv 前调用，读取文件并校验
 * 
 * @return 0=校验通过, -1=校验失败
 */
PRIVATE int shell_verify_integrity(const char *path)
{
	/* 确保表已初始化 */
	if (!trusted_table_init) init_trusted_table();
	
	/* 读取文件 */
	struct stat fstat;
	if (stat(path, &fstat) != 0) {
		printf("{INTEGRITY} [ERROR] Cannot stat file: %s\n", path);
		return -1;
	}
	
	int fd = open(path, O_RDWR);
	if (fd == -1) {
		printf("{INTEGRITY} [ERROR] Cannot open file: %s\n", path);
		return -1;
	}
	
	/* 使用栈上的缓冲区读取文件 (限制大小) */
	char buf[SECTOR_SIZE * 32]; /* 16KB 缓冲区 */
	int file_size = fstat.st_size;
	if (file_size > sizeof(buf)) {
		printf("{INTEGRITY} [WARN] File too large, using partial check\n");
		file_size = sizeof(buf);
	}
	
	int bytes_read = read(fd, buf, file_size);
	close(fd);
	
	if (bytes_read != file_size) {
		printf("{INTEGRITY} [ERROR] Read failed for: %s\n", path);
		return -1;
	}
	
	/* 计算 CRC32 */
	unsigned int crc = calc_crc32(buf, file_size);
	
	/* 提取文件名 */
	const char *name = path;
	const char *p = path;
	while (*p) {
		if (*p == '/') name = p + 1;
		p++;
	}
	
	/* 查找可信表 */
	int idx = find_trusted_prog(name);
	
	if (idx < 0) {
		/* 首次加载 - 学习模式 */
		printf("{INTEGRITY} [LEARN] %s: CRC32=0x%x (recorded)\n", name, crc);
		add_trusted_prog(name, crc);
		return 0;
	}
	
	/* 验证 CRC32 */
	if (trusted_progs[idx].crc32 == crc) {
		printf("{INTEGRITY} [PASS] %s: CRC32=0x%x OK\n", name, crc);
		return 0;
	} else {
		printf("{INTEGRITY} [FAIL] %s: Expected=0x%x, Got=0x%x\n", 
		       name, trusted_progs[idx].crc32, crc);
		printf("{INTEGRITY} [BLOCKED] Integrity violation detected!\n");
		return -1;
	}
}

/*****************************************************************************
 *                                shabby_shell
 *****************************************************************************/
/**
 * A very very simple shell.
 * 
 * @param tty_name  TTY file name.
 *****************************************************************************/
void shabby_shell(const char * tty_name)
{
	int fd_stdin  = open(tty_name, O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];

	while (1) {
		write(1, "$ ", 2);

		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;

        char * current_cmd = rdbuf; // 指向当前要处理的命令段
        while (current_cmd != 0 && *current_cmd != 0) {
            // 寻找 & 符号的位置
            char * next_cmd = 0;
            char * temp = current_cmd;
            while (*temp) {
                if (*temp == '&') {
                    // 找到了 &
                    *temp = 0;       // 将& 替换为结束符 \0，切断字符串
                    next_cmd = temp + 1; // 下一条命令开始于 & 之后
                    break;
                }
                temp++;
            }

            int argc = 0;
            char * argv[PROC_ORIGIN_STACK];
            char * p = current_cmd; 
            char * s;
            int word = 0;
            char ch;
            do {
                ch = *p;
                if (*p != ' ' && *p != 0 && !word) {
                    s = p;
                    word = 1;
                }
                if ((*p == ' ' || *p == 0) && word) {
                    word = 0;
                    argv[argc++] = s;
                    *p = 0;
                }
                p++;
            } while(ch);
            argv[argc] = 0;

            // 执行命令
            if (argv[0] == 0) {
                // 如果是空命令（比如输入了 "echo a & & echo b"），直接跳过
                current_cmd = next_cmd;
                continue;
            }

            /* ===== 命令查找与加载流程 ===== */
            printf("{SHELL} [LOOKUP] Searching for command: %s\n", argv[0]);
            
            int fd = open(argv[0], O_RDWR);
            if (fd == -1) {
                printf("{SHELL} [NOT_FOUND] Command not found: %s\n", argv[0]);
                if (current_cmd[0]) {
                    write(1, "{", 1);
                    write(1, current_cmd, strlen(current_cmd));
                    write(1, "}\n", 2);
                }
            }
            else {
                printf("{SHELL} [FOUND] Command exists: %s\n", argv[0]);
                close(fd);
                
                printf("{SHELL} [FORK] Creating child process for: %s\n", argv[0]);
                int pid = fork();
                if (pid != 0) { 
                    printf("{SHELL} [PARENT] Child PID=%d, waiting...\n", pid);
                    int s;
                    // 并行执行的关键点
                    // 如果想要完全并行，需要把 wait 注释掉，但完全的并行会导致输出混乱
                    wait(&s); 
                    printf("{SHELL} [PARENT] Child exited with status=%d\n", s);
                }
                else {  
                    /* ===== 完整性校验 ===== */
                    printf("{SHELL} [VERIFY] Checking integrity of: %s\n", argv[0]);
                    if (shell_verify_integrity(argv[0]) != 0) {
                        printf("{SHELL} [BLOCKED] Execution denied!\n");
                        exit(1); /* 校验失败，子进程退出 */
                    }
                    printf("{SHELL} [EXEC] Launching: %s\n", argv[0]);
                    execv(argv[0], argv);
                }
            }
            // 移动到下一条命令
            current_cmd = next_cmd;
        }
    }

    close(1);
    close(0);
}

/*****************************************************************************
 *                                Init
 *****************************************************************************/
/**
 * The hen.
 * 
 *****************************************************************************/
void Init()
{
	int fd_stdin  = open("/dev_tty0", O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open("/dev_tty0", O_RDWR);
	assert(fd_stdout == 1);

	printf("Init() is running ...\n");

	/* extract `cmd.tar' */
	untar("/cmd.tar");
			

	char * tty_list[] = {"/dev_tty1", "/dev_tty2"};

	int i;
	for (i = 0; i < sizeof(tty_list) / sizeof(tty_list[0]); i++) {
		int pid = fork();
		if (pid != 0) { /* parent process */
			printf("[parent is running, child pid:%d]\n", pid);
		}
		else {	/* child process */
			printf("[child is running, pid:%d]\n", getpid());
			close(fd_stdin);
			close(fd_stdout);
			
			shabby_shell(tty_list[i]);
			assert(0);
		}
	}

	while (1) {
		int s;
		int child = wait(&s);
		printf("child (%d) exited with status: %d.\n", child, s);
	}

	assert(0);
}


/*======================================================================*
                               TestA
 *======================================================================*/
void TestA()
{
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestB()
{
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestC()
{
	for(;;);
}

/*****************************************************************************
 *                                panic
 *****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}

