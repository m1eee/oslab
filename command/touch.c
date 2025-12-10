#include "cmd_head.h"
int main(int argc, char *argv[]){
	if (argc < 2){
		printf("Usage: touch <filename>\n");
		return 1;
	}
	int fd = open(argv[1], O_CREAT);
	if (fd == -1){
		printf("Failed to create %s \n", argv[1]);
		return 1;
	}
	printf("Create %s success\n", argv[1]);
	close(fd);
	return 0;
}