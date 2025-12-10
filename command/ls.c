#include "cmd_head.h"

PRIVATE char* get_file_type_name(char* filename);

int main(int argc, char *argv[]){
	MESSAGE msg;
    char file[DIR_ENTRY_SIZE * 64];

	msg.type = LS;
	msg.BUF = (void *)file;

	send_recv(BOTH, TASK_FS, &msg);
	if (msg.type != SYSCALL_RET) return -1;

    struct dir_entry *pde = (struct dir_entry *)msg.BUF;

    printf(" inode       type       size    name\n");
    printf("------------------------------------\n");

    char filename[MAX_FILENAME_LEN + 1];
    struct stat s; // 用于接收文件属性

    for (int i = 0; i < msg.CNT; i++) {
        // 获取文件名
        memcpy(filename, pde->name, MAX_FILENAME_LEN);
        filename[MAX_FILENAME_LEN] = 0;

        // 调用 stat 获取详细属性
        int ret = stat(filename, &s);
        
        if (ret != 0) {
            printf("%5d   ?       ?       %s\n", pde->inode_nr, filename);
        } else {
            // 解析文件类型 
            char *type_str = "Unknown";
            if (s.st_mode & I_DIRECTORY) {
                type_str = "Dir";
            } 
            else if (s.st_mode & I_CHAR_SPECIAL) {
                type_str = "CharDev";
            } 
            else {
                // 如果是普通文件，则通过后缀判断 
                type_str = get_file_type_name(filename);
            }
            
            // 打印详细信息 %5d: Inode号 %12s : 文件类型 
            // %7d: 文件大小 (字节)  %s : 文件名
            printf("%5d    %8s    %7d    %s\n", 
                   s.st_ino, type_str, s.st_size, filename);
        }
        pde++; // 指向下一个目录项
    }
	return msg.RETVAL;
}

/* 辅助函数：根据后缀名判断类型 */
PRIVATE char* get_file_type_name(char* filename)
{
    int len = strlen(filename);
    int i;
    char* ext = 0;

    // 从后往前找 '.' 
    for (i = len - 1; i >= 0; i--) {
        if (filename[i] == '.') {
            ext = &filename[i]; 
            break;
        }
    }
    if (ext == 0 || strlen(ext) <= 1) {
        return "bin"; // 默认为二进制/ELF 
    }

    // 比较后缀名 
    if (strcmp(ext, ".tar") == 0) {
        return "tar";
    }
    else if (strcmp(ext, ".txt") == 0) {
        return "txt";
    }

    // 未知后缀也默认为 Binary 
    return "bin";
}