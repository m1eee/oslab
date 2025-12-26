/*************************************************************************//**
 *****************************************************************************
 * @file   syscall_hook.c
 * @brief  System Call Hook - 参数验证与安全检查
 *****************************************************************************
 *****************************************************************************/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "fs.h"
#include "tty.h"
#include "console.h"
#include "proc.h"
#include "global.h"
#include "proto.h"

/* Hook 开关：1 = 启用，0 = 禁用 */
PUBLIC int syscall_hook_enabled = 1;

/*****************************************************************************
 *                              syscall_hook_check
 *****************************************************************************/
/**
 * <Ring 0> 系统调用参数验证 Hook
 * 
 * @param function  SEND 或 RECEIVE
 * @param src_dest  目标/源进程号
 * @param m         消息指针
 * @param p         调用者进程
 * 
 * @return 0 = 通过，非0 = 拒绝
 *****************************************************************************/
PUBLIC int syscall_hook_check(int function, int src_dest, MESSAGE* m, struct proc* p)
{
	int caller = proc2pid(p);
	
	/* 1. 验证 function 参数 */
	if (function != SEND && function != RECEIVE) {
		return -1;  /* 非法操作类型 */
	}
	
	/* 2. 验证 src_dest 范围 */
	if (src_dest != ANY && src_dest != INTERRUPT) {
		if (src_dest < 0 || src_dest >= NR_TASKS + NR_PROCS) {
			return -2;  /* 目标进程号越界 */
		}
		/* 禁止向自身发送消息 */
		if (src_dest == caller) {
			return -3;  /* 不能向自己发消息 */
		}
	}
	
	/* 3. 验证消息指针 */
	if (m == 0) {
		return -4;  /* 空消息指针 */
	}
	
	/* 4. 普通用户进程不能直接向系统任务发送危险消息 */
	if (caller >= NR_TASKS && function == SEND) {
		MESSAGE* mla = (MESSAGE*)va2la(caller, m);
		/* 限制用户进程发送的消息类型 */
		int msg_type = mla->type;
		
		/* 禁止用户进程伪造 HARD_INT */
		if (msg_type == HARD_INT) {
			return -5;  /* 用户进程不能发送硬件中断消息 */
		}
	}
	
	return 0;  /* 验证通过 */
}
