/*************************************************************************//**
 *****************************************************************************
 * @file   mm/integrity.c
 * @brief  可执行文件完整性校验模块
 * @author OS Lab
 * @date   2024
 * 
 * 本模块实现基于 CRC32 的可执行文件完整性校验机制。
 * 
 * 设计说明：
 * 1. 校验算法使用 CRC32，相比奇偶校验具有更强的错误检测能力
 * 2. 校验值存储在内核内存的静态表中（白名单机制）
 * 3. 在 exec 系统调用加载可执行文件时进行校验
 * 
 * 安全性分析：
 * - CRC32 可检测任意奇数位错误和大多数偶数位错误
 * - 对于恶意篡改，CRC32 并非密码学安全，但对于教学目的足够
 * - 奇偶校验只能检测奇数位错误，无法检测偶数位篡改
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
 *                          CRC32 校验算法实现                                *
 *===========================================================================*/

/* CRC32 多项式 (IEEE 802.3 标准) */
#define CRC32_POLYNOMIAL 0xEDB88320

/* CRC32 查找表 - 在首次使用时初始化 */
PRIVATE u32 crc32_table[256];
PRIVATE int crc32_table_initialized = 0;

/*****************************************************************************
 *                              init_crc32_table
 *****************************************************************************/
/**
 * 初始化 CRC32 查找表
 *****************************************************************************/
PRIVATE void init_crc32_table()
{
    u32 i, j, crc;
    
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
            else
                crc = crc >> 1;
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = 1;
}

/*****************************************************************************
 *                              calculate_crc32
 *****************************************************************************/
/**
 * 计算数据的 CRC32 校验值
 * 
 * @param data   数据缓冲区指针
 * @param len    数据长度（字节）
 * @return       CRC32 校验值
 *****************************************************************************/
PUBLIC u32 calculate_crc32(const u8 *data, u32 len)
{
    u32 crc = 0xFFFFFFFF;
    u32 i;
    
    /* 确保 CRC32 表已初始化 */
    if (!crc32_table_initialized) {
        init_crc32_table();
    }
    
    for (i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    
    return crc ^ 0xFFFFFFFF;
}

/*===========================================================================*
 *                          可信程序白名单管理                                 *
 *===========================================================================*/

/* 最大可信程序数量 */
#define MAX_TRUSTED_PROGRAMS 16

/* 最大程序名长度 */
#define MAX_PROG_NAME_LEN 16

/**
 * 可信程序条目结构
 */
struct trusted_entry {
    char name[MAX_PROG_NAME_LEN];  /* 程序名（如 "echo", "ls"） */
    u32  crc32;                     /* 预期的 CRC32 值 */
    int  valid;                     /* 条目是否有效 */
};

/* 可信程序白名单表 */
PRIVATE struct trusted_entry trusted_table[MAX_TRUSTED_PROGRAMS];
PRIVATE int trusted_table_initialized = 0;

/*****************************************************************************
 *                          init_trusted_table
 *****************************************************************************/
/**
 * 初始化可信程序表
 * 
 * 注意：这里的 CRC32 值需要在系统首次部署时预先计算并填入。
 * 在实际部署时，应通过安全渠道获取这些值。
 * 
 * 对于教学演示，这里将所有程序的预期值设为 0，表示"学习模式"：
 * - 首次加载时计算并记录 CRC32
 * - 后续加载时与记录值比对
 *****************************************************************************/
PRIVATE void init_trusted_table()
{
    int i;
    
    for (i = 0; i < MAX_TRUSTED_PROGRAMS; i++) {
        trusted_table[i].name[0] = '\0';
        trusted_table[i].crc32 = 0;
        trusted_table[i].valid = 0;
    }
    
    trusted_table_initialized = 1;
    printl("{INTEGRITY} Trusted program table initialized.\n");
}

/*****************************************************************************
 *                          extract_filename
 *****************************************************************************/
/**
 * 从完整路径中提取文件名
 * 
 * @param pathname  完整路径
 * @param filename  输出文件名缓冲区
 *****************************************************************************/
PRIVATE void extract_filename(const char *pathname, char *filename)
{
    const char *p = pathname;
    const char *last_slash = pathname;
    
    /* 找到最后一个 '/' */
    while (*p) {
        if (*p == '/')
            last_slash = p + 1;
        p++;
    }
    
    /* 复制文件名 */
    int i = 0;
    while (*last_slash && i < MAX_PROG_NAME_LEN - 1) {
        filename[i++] = *last_slash++;
    }
    filename[i] = '\0';
}

/*****************************************************************************
 *                          find_trusted_entry
 *****************************************************************************/
/**
 * 在可信表中查找指定程序
 * 
 * @param name   程序名
 * @return       找到返回条目索引，否则返回 -1
 *****************************************************************************/
PRIVATE int find_trusted_entry(const char *name)
{
    int i;
    
    for (i = 0; i < MAX_TRUSTED_PROGRAMS; i++) {
        if (trusted_table[i].valid) {
            /* 简单字符串比较 */
            const char *p1 = trusted_table[i].name;
            const char *p2 = name;
            int match = 1;
            
            while (*p1 && *p2) {
                if (*p1 != *p2) {
                    match = 0;
                    break;
                }
                p1++;
                p2++;
            }
            if (*p1 != *p2)
                match = 0;
            
            if (match)
                return i;
        }
    }
    
    return -1;
}

/*****************************************************************************
 *                          add_trusted_entry
 *****************************************************************************/
/**
 * 添加新的可信程序条目
 * 
 * @param name   程序名
 * @param crc32  CRC32 校验值
 * @return       成功返回 0，失败返回 -1
 *****************************************************************************/
PRIVATE int add_trusted_entry(const char *name, u32 crc32)
{
    int i;
    
    /* 查找空闲条目 */
    for (i = 0; i < MAX_TRUSTED_PROGRAMS; i++) {
        if (!trusted_table[i].valid) {
            /* 复制程序名 */
            const char *src = name;
            char *dst = trusted_table[i].name;
            int j = 0;
            
            while (*src && j < MAX_PROG_NAME_LEN - 1) {
                dst[j++] = *src++;
            }
            dst[j] = '\0';
            
            trusted_table[i].crc32 = crc32;
            trusted_table[i].valid = 1;
            
            return 0;
        }
    }
    
    return -1; /* 表已满 */
}

/*===========================================================================*
 *                          对外接口：完整性校验                               *
 *===========================================================================*/

/*****************************************************************************
 *                          verify_executable_integrity
 *****************************************************************************/
/**
 * 验证可执行文件完整性
 * 
 * 本函数在可执行文件加载前被调用，对文件内容进行 CRC32 校验。
 * 
 * 工作模式：
 * 1. 如果程序首次加载（不在可信表中），计算 CRC32 并记录，允许加载
 * 2. 如果程序已在可信表中，比对 CRC32，匹配则允许，不匹配则拒绝
 * 
 * @param pathname   可执行文件路径
 * @param file_data  文件数据指针
 * @param file_size  文件大小
 * @return           0 = 校验通过，-1 = 校验失败
 *****************************************************************************/
PUBLIC int verify_executable_integrity(const char *pathname, 
                                        const u8 *file_data, 
                                        u32 file_size)
{
    char filename[MAX_PROG_NAME_LEN];
    u32 computed_crc;
    int entry_idx;
    
    /* 确保可信表已初始化 */
    if (!trusted_table_initialized) {
        init_trusted_table();
    }
    
    /* 提取文件名 */
    extract_filename(pathname, filename);
    
    /* 计算文件 CRC32 */
    computed_crc = calculate_crc32(file_data, file_size);
    
    /* 查找可信表 */
    entry_idx = find_trusted_entry(filename);
    
    if (entry_idx < 0) {
        /* 首次加载：记录到可信表（学习模式） */
        if (add_trusted_entry(filename, computed_crc) == 0) {
            printl("{INTEGRITY} [LEARN] %s: CRC32=0x%x (recorded)\n", 
                   filename, computed_crc);
        } else {
            printl("{INTEGRITY} [WARN] Trusted table full, cannot record %s\n", 
                   filename);
        }
        return 0; /* 首次加载允许通过 */
    }
    
    /* 已有记录：比对 CRC32 */
    if (trusted_table[entry_idx].crc32 == computed_crc) {
        printl("{INTEGRITY} [PASS] %s: CRC32=0x%x verified\n", 
               filename, computed_crc);
        return 0; /* 校验通过 */
    } else {
        printl("{INTEGRITY} [FAIL] %s: CRC32 mismatch! Expected=0x%x, Got=0x%x\n", 
               filename, trusted_table[entry_idx].crc32, computed_crc);
        printl("{INTEGRITY} [BLOCKED] Execution denied due to integrity violation!\n");
        return -1; /* 校验失败，拒绝加载 */
    }
}
