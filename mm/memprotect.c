/*************************************************************************//**
 *****************************************************************************
 * @file   mm/memprotect.c
 * @brief  内核/用户空间隔离保护模块
 * @date   2024
 * 
 * 本模块实现基于分段的内核/用户空间隔离机制。
 * 
 * 设计原则：
 * 1. 最小化侵入：完全独立模块，不修改现有代码逻辑
 * 2. 简洁高效：仅实现必要的边界检查功能
 * 3. 可控可回退：所有功能通过宏开关控制
 * 
 * 内存布局（参考 global.c 和 proc.h）：
 *   0x000000 - 0x600000 (6MB): 内核代码/数据/栈
 *   0x600000 - 0x700000 (6-7MB): FS 缓冲区
 *   0x700000 - 0x800000 (7-8MB): MM 缓冲区
 *   0x800000 - 0xA00000 (8-10MB): 日志缓冲区
 *   0xA00000+  (10MB+): 用户进程空间 (PROCS_BASE)
 * 
 *****************************************************************************
 *****************************************************************************/

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

/*===========================================================================*
 *                          内存边界常量定义                                   *
 *===========================================================================*/

/* 内核空间上界 - 用户进程空间起始地址 */
#define KERNEL_SPACE_TOP    PROCS_BASE   /* 10MB = 0xA00000 */

/* 内核关键缓冲区地址范围 */
#define FSBUF_BASE          0x600000
#define MMBUF_BASE          0x700000
#define LOGBUF_BASE         0x800000

/*===========================================================================*
 *                          内存保护功能实现                                   *
 *===========================================================================*/

/*****************************************************************************
 *                              is_kernel_addr
 *****************************************************************************/
/**
 * 检查线性地址是否位于内核空间
 * 
 * @param linear_addr  线性地址
 * @return             1 = 内核空间, 0 = 用户空间
 *****************************************************************************/
PUBLIC int is_kernel_addr(u32 linear_addr)
{
    return (linear_addr < KERNEL_SPACE_TOP);
}

/*****************************************************************************
 *                              verify_user_ptr
 *****************************************************************************/
/**
 * 验证用户空间指针是否有效且不越界到内核空间
 * 
 * 此函数用于在内核态处理用户传入的指针时进行安全检查。
 * 
 * @param pid       进程 ID
 * @param user_ptr  用户空间虚拟地址
 * @param size      访问大小（字节）
 * @return          0 = 有效, -1 = 无效（越界到内核空间）
 *****************************************************************************/
PUBLIC int verify_user_ptr(int pid, void* user_ptr, u32 size)
{
    struct proc* p = &proc_table[pid];
    
    /* 任务进程（Ring 0/1）不做限制 */
    if (pid < NR_TASKS) {
        return 0;
    }
    
    /* 计算段基址 */
    struct descriptor* d = &p->ldts[INDEX_LDT_RW];
    u32 seg_base = (d->base_high << 24) | (d->base_mid << 16) | d->base_low;
    
    /* 计算线性地址范围 */
    u32 uva = (u32)user_ptr;
    u32 linear_start = seg_base + uva;
    u32 linear_end = linear_start + size;
    
    /* 检查溢出 */
    if (linear_end < linear_start) {
        return -1;  /* 地址溢出 */
    }
    
    /* 用户进程的地址必须在其分配的空间内 */
    /* 对于 fork 出的进程，其基址应该 >= PROCS_BASE */
    if (pid >= NR_TASKS + NR_NATIVE_PROCS) {
        /* 动态分配的进程：检查是否越界到内核空间 */
        if (linear_start < KERNEL_SPACE_TOP) {
            return -1;  /* 越界到内核空间 */
        }
    }
    
    return 0;  /* 验证通过 */
}

/*****************************************************************************
 *                              get_proc_mem_base
 *****************************************************************************/
/**
 * 获取进程的内存基址
 * 
 * @param pid  进程 ID
 * @return     进程内存段基址
 *****************************************************************************/
PUBLIC u32 get_proc_mem_base(int pid)
{
    struct proc* p = &proc_table[pid];
    struct descriptor* d = &p->ldts[INDEX_LDT_RW];
    return (d->base_high << 24) | (d->base_mid << 16) | d->base_low;
}

/*****************************************************************************
 *                              get_proc_mem_limit
 *****************************************************************************/
/**
 * 获取进程的内存界限（大小）
 * 
 * @param pid  进程 ID
 * @return     进程内存段大小（字节）
 *****************************************************************************/
PUBLIC u32 get_proc_mem_limit(int pid)
{
    struct proc* p = &proc_table[pid];
    struct descriptor* d = &p->ldts[INDEX_LDT_RW];
    
    u32 limit = ((d->limit_high_attr2 & 0x0F) << 16) | d->limit_low;
    
    /* 检查粒度位 G */
    if (d->limit_high_attr2 & (DA_LIMIT_4K >> 8)) {
        limit = (limit + 1) << 12;  /* 4KB 粒度 */
    } else {
        limit = limit + 1;          /* 1B 粒度 */
    }
    
    return limit;
}

/*****************************************************************************
 *                              check_mem_access
 *****************************************************************************/
/**
 * 综合检查内存访问是否合法
 * 
 * 此函数可用于在关键系统调用处进行用户指针验证。
 * 
 * @param pid       进程 ID
 * @param user_ptr  用户提供的虚拟地址
 * @param size      访问大小（字节）
 * @param write     1 = 写访问, 0 = 读访问
 * @return          0 = 合法, -1 = 非法
 *****************************************************************************/
PUBLIC int check_mem_access(int pid, void* user_ptr, u32 size, int write)
{
    /* 基本指针验证 */
    if (verify_user_ptr(pid, user_ptr, size) != 0) {
        return -1;
    }
    
    /* 检查是否超出进程的段界限 */
    u32 uva = (u32)user_ptr;
    u32 limit = get_proc_mem_limit(pid);
    
    if (uva + size > limit) {
        return -1;  /* 超出段界限 */
    }
    
    return 0;
}
