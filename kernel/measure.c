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
#include "config.h"

#define MAX_FRAMES 16

u32 get_base(struct descriptor* d)
{
    return (d->base_low |
           (d->base_mid << 16) |
           (d->base_high << 24));
}

u32 get_limit(struct descriptor* d)
{
    u32 limit = (d->limit_low | ((d->limit_high_attr2 & 0x0F) << 16));
    if (d->limit_high_attr2 & 0x80) { /* G=1 粒度 4KB */
        limit = (limit << 12) | 0xFFF;
    }
    return limit;
}

PUBLIC void do_measure_current()
{
    struct proc* p = p_proc_ready;
    int pid = (int)(p - proc_table);

    /* 跳过内核任务/系统任务，只检查用户进程 */
    if (pid < NR_TASKS) return;
    
    // printl("[measure] Measuring\n");

    /* 取 code/data 段布局（LDT） */
    struct descriptor* dc = &p->ldts[INDEX_LDT_C];
    struct descriptor* dd = &p->ldts[INDEX_LDT_RW];

    u32 code_base  = get_base(dc);
    u32 code_limit = get_limit(dc);   
    u32 data_base  = get_base(dd);
    u32 data_limit = get_limit(dd);

    /* 当前栈指针/帧指针（寄存器保存在 p->regs 里，字段名可能是 esp/ebp） */
    u32 ebp = p->regs.ebp;
    u32 esp = p->regs.esp;

    /* 基础边界检查：EBP/ESP 必须在 data 段内 */
    if (ebp > data_limit || esp > data_limit) {
        printl("bad esp/ebp\n");
        return;
    }

    int bad = 0;
    u32 cur = ebp;

    for (int depth = 0; depth < MAX_FRAMES; depth++) {
        /* 需要读 [cur] 和 [cur+4]，所以 cur+8 不能越界 */
        if (cur == 0 || cur + 8 > data_limit) { bad = 1; break; }

        /* 把“段内偏移”转成线性地址再读 */
        u32* p_prev = (u32*)(data_base + cur);
        u32* p_ret  = (u32*)(data_base + cur + 4);

        u32 prev_ebp = *p_prev;
        u32 ret_eip  = *p_ret;

        /* 返回地址合法性：必须落在 code 段 limit 内 */
        if (ret_eip > code_limit) {
            printl("bad ret\n");
            bad = 1;
            break;
        }

        /* EBP 链合法性：必须向“更老的栈帧”移动（地址增大） */
        if (prev_ebp == 0) {
            break;  // 正常到头
        }
        if (prev_ebp <= cur || prev_ebp > data_limit) {
            printl("bad ebp chain\n");
            bad = 1;
            break;
        }

        cur = prev_ebp;
    }

}
