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

#define KLOG_BUF_SIZE 4096

PRIVATE char klog_buf[KLOG_BUF_SIZE];
PRIVATE int klog_head = 0;
PRIVATE int klog_tail = 0;

/* Log Masks Switch - Default to ALL for demonstration */


/* 
 * Helper to get time safely.
 * We can't use IPC to TASK_SYS here if we are called from schedule() or inside an IPC.
 * So we read CMOS directly.
 * Note: This might be slow.
 */
PRIVATE void get_time_string(char * buf)
{
    /* Simple CMOS read */
    /* Accessing ports 0x70/0x71 */
    /* Note: Ideally disable interrupts around this if not already disabled */
    
    int year, month, day, hour, minute, second;

    /* Read Status B to check BCD */
    out_byte(CLK_ELE, CLK_STATUS);
    int status = in_byte(CLK_IO);
    int is_bcd = !(status & 0x04);

    out_byte(CLK_ELE, YEAR); year = in_byte(CLK_IO);
    out_byte(CLK_ELE, MONTH); month = in_byte(CLK_IO);
    out_byte(CLK_ELE, DAY); day = in_byte(CLK_IO);
    out_byte(CLK_ELE, HOUR); hour = in_byte(CLK_IO);
    out_byte(CLK_ELE, MINUTE); minute = in_byte(CLK_IO);
    out_byte(CLK_ELE, SECOND); second = in_byte(CLK_IO);

    if (is_bcd) {
        #define BCD_TO_DEC(x) ((x >> 4) * 10 + (x & 0x0f))
        year = BCD_TO_DEC(year);
        month = BCD_TO_DEC(month);
        day = BCD_TO_DEC(day);
        hour = BCD_TO_DEC(hour);
        minute = BCD_TO_DEC(minute);
        second = BCD_TO_DEC(second);
    }

    year += 2000; // Assume 20xx
    
    // Timezone UTC+8
    hour += 8;
    if (hour >= 24) {
        hour -= 24;
        day++; // Simplified. Doesn't handle month rollover.
    }

    sprintf(buf, "%02d:%02d:%02d", hour, minute, second);
}

PUBLIC void klog(int type, char *fmt, ...)
{
    if (!(LOG_ALL & type)) return;

    char buf[256];
    char time_str[16];
    va_list args = (va_list)((char*)(&fmt) + 4);

    get_time_string(time_str);

    int i = sprintf(buf, "[%s] ", time_str);
    i += vsprintf(buf + i, fmt, args);
    
    /* Write to Ring Buffer */
    disable_int();
    int j;
    for (j = 0; j < i; j++) {
        klog_buf[klog_head] = buf[j];
        klog_head = (klog_head + 1) % KLOG_BUF_SIZE;
        if (klog_head == klog_tail) {
            klog_tail = (klog_tail + 1) % KLOG_BUF_SIZE; // Overwrite oldest
        }
    }
    enable_int();
}

PUBLIC int sys_getklog(int _unused1, int _unused2, char* buf, struct proc* p_proc)
{
    /* Copy from Ring Buffer to User Buffer */
    int len = 0;
    int max_len = 1024; /* Arbitrary chunk size for one syscall */
    char temp[1024];

    disable_int();
    while (klog_tail != klog_head && len < max_len - 1) {
        temp[len++] = klog_buf[klog_tail];
        klog_tail = (klog_tail + 1) % KLOG_BUF_SIZE;
    }
    enable_int();
    
    temp[len] = 0;

    if (len > 0) {
        phys_copy(va2la(proc2pid(p_proc), buf),
                  va2la(proc2pid(proc_table + TASK_SYS), temp), /* We are in Ring 0/Kernel, usually effectively TASK_SYS context or similar linear mapping */
                  len + 1);
    } else {
        /* Write empty string */
        char null_char = 0;
        phys_copy(va2la(proc2pid(p_proc), buf),
                  va2la(proc2pid(proc_table + TASK_SYS), &null_char),
                  1);
    }
    
    return len;
}
