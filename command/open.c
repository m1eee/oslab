#include "cmd_head.h"
void edit(int fd, char *filename);
int strncmp(char *s1, char *s2, int n);
int elf_test(const char *filename);

int main(int argc, char *argv[]){
	if (argc < 2){
		printf("Usage: open <filename>\n");
		return 1;
	}

	const char *filename = argv[1];
	int fd;
    // 首先尝试运行文件
	if (elf_test(filename)){
		printf("Run: %s\n", filename);
		execl(filename, filename);
		return 1;
	}else{ // 运行失败则编辑文件
		fd = open(filename, O_RDWR);
		if (fd < 0){
			printf("Failed to open %s\n", filename);
			return 1;
		}
		edit(fd, argv[1]);
		close(fd);
	}
	return 0;
}

void edit(int fd, char *filename){
	int BUFFER_SIZE = 256;
	char buf[BUFFER_SIZE];
	char f[BUFFER_SIZE * 10];
	int n = read(fd, f, BUFFER_SIZE * 10 - 1);
	if (n < 0){
		printf("Cannot read file\n");
		return;
	}
	printf("%s:\n",filename);
	write(1, f, strlen(f));
    // add text:添加文本
    // del num:删除最后num个字符
    // s:保存并退出
	printf("\nUsage: add, del, s\n");
	while (1){
		printf("\n>");
		int length = read(0, buf, BUFFER_SIZE - 1);
        if(length <= 0) continue;
		buf[length] = '\0';

		if (strcmp(buf, "s") == 0) break;
		else if (strncmp(buf, "add ", 4) == 0){
			strcat(f, buf + 4);
			strcat(f, "\n");
		}
		else if (strncmp(buf, "del ", 4) == 0){
			int num = atoi(buf + 4);
			if (num > strlen(f)){
				printf("error length\n");
				continue;
			}
			u64 new_len = strlen(f) - (u64)num;
			f[new_len] = '\0';
		}
		else{
			printf("error command\n");
			continue;
		}
	}

	fd = open(filename, O_RDWR | O_TRUNC);
	lseek(fd, 0, SEEK_SET);

	write(fd, f, strlen(f));
	printf("%s:\n\n",filename);
	write(1, f, strlen(f));
	printf("\n\nfile saved\n");
}

int strncmp(char *s1, char *s2, int n){
	for (int i = 0; i < n; i++){
		if (s1[i] != s2[i]) return 1;
		if (s1[i] == '\0') return 0;
	}
	return 0;
}
int elf_test(const char *filename){
	int fd = open(filename, O_RDWR);
	if (fd < 0){
		printf("Failed to open %s\n", filename);
		return 0;
	}
	lseek(fd, 0, SEEK_SET);

	char header[16];
	int length = read(fd, header, 16);
	close(fd);

	if (length < 16) return 0;

	if (strncmp(header, "\177ELF", 4) == 0) return 1;
	else return 0;
}
