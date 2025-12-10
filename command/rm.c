#include "cmd_head.h"
int main(int argc, char *argv[]){
	if (argc < 2){
		printf("Usage: rm <filename>\n");
		return 1;
	}
	int res = unlink(argv[1]);
	if (res == -1){
		printf("Failed to remove %s\n", argv[1]);
		return 1;
	}
	else{
		printf("Remove %s success\n", argv[1]);
	}
	return 0;
}