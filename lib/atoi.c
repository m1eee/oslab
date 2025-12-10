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

PUBLIC int atoi(char *s){
	int res = 0;
	while (*s <= '9' && *s >= '0'){
		res = res * 10 + *s - '0';
		s++;
	}
	return res;
}