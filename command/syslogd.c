#include "stdio.h"
#include "const.h"
#include "string.h"

#define PUBLIC

/* System call declarations */
PUBLIC int getklog(char * buf);
PUBLIC int setlogctrl(int enabled, int mask);

/* Log type masks (must match kernel const.h) */
#define LOG_SCHED   0x01
#define LOG_FS      0x02
#define LOG_SYSCALL 0x04
#define LOG_DEV     0x08
#define LOG_ALL     0x0F

/* 
 * syslogd.c
 * System Log Control for Orange'S
 * 
 * Usage:
 *   syslogd -on           Enable logging (all categories)
 *   syslogd -off          Disable logging
 *   syslogd -status       Show current log status
 *   syslogd -proc         Enable only process/scheduler logging
 *   syslogd -fs           Enable only filesystem logging
 *   syslogd -syscall      Enable only syscall logging
 *   syslogd -dev          Enable only device logging
 *   syslogd -all          Enable all categories
 *   syslogd -dump         Dump current log buffer to /syslog
 */

static void print_usage()
{
    printf("Usage: syslogd <options>\n");
    printf("  -on       Enable logging\n");
    printf("  -off      Disable logging\n");
    printf("  -proc     Add scheduler log\n");
    printf("  -fs       Add filesystem log\n");
    printf("  -syscall  Add syscall log\n");
    printf("  -dev      Add device log\n");
    printf("  -all      Log all categories\n");
    printf("  -dump     Dump log to /syslog\n");
    printf("Example: syslogd -on -proc -fs\n");
}

static int dump_log()
{
    int fd;
    char buf[1024];
    int n, total = 0;

    fd = open("/syslog", O_CREAT | O_RDWR);
    if (fd == -1) {
        printf("syslogd: failed to open /syslog\n");
        return 1;
    }

    /* Read and write in a loop, but with a limit to avoid hanging */
    int iterations = 0;
    while (iterations < 100) {  /* Max 100 iterations */
        n = getklog(buf);
        if (n > 0) {
            write(fd, buf, n);
            total += n;
        } else {
            break;  /* No more data, stop */
        }
        iterations++;
    }

    close(fd);
    printf("syslogd: dumped %d bytes to /syslog\n", total);
    return 0;
}

int main(int argc, char * argv[])
{
    int mask = 0;
    int enabled = -1;  /* -1 = not set, 0 = off, 1 = on */
    int do_dump = 0;
    int i;

    if (argc < 2) {
        print_usage();
        return 0;
    }

    /* Parse all arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-on") == 0) {
            enabled = 1;
        }
        else if (strcmp(argv[i], "-off") == 0) {
            enabled = 0;
        }
        else if (strcmp(argv[i], "-proc") == 0) {
            mask |= LOG_SCHED;
        }
        else if (strcmp(argv[i], "-fs") == 0) {
            mask |= LOG_FS;
        }
        else if (strcmp(argv[i], "-syscall") == 0) {
            mask |= LOG_SYSCALL;
        }
        else if (strcmp(argv[i], "-dev") == 0) {
            mask |= LOG_DEV;
        }
        else if (strcmp(argv[i], "-all") == 0) {
            mask = LOG_ALL;
        }
        else if (strcmp(argv[i], "-dump") == 0) {
            do_dump = 1;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage();
            return 1;
        }
    }

    /* Handle dump first */
    if (do_dump) {
        return dump_log();
    }

    /* If no mask specified but turning on, use all */
    if (enabled == 1 && mask == 0) {
        mask = LOG_ALL;
    }

    /* Apply settings */
    if (enabled == 1) {
        setlogctrl(1, mask);
        printf("syslogd: logging ENABLED (mask=0x%x)\n", mask);
    }
    else if (enabled == 0) {
        setlogctrl(0, 0);
        printf("syslogd: logging DISABLED\n");
    }
    else if (mask != 0) {
        /* Only mask specified, assume enable */
        setlogctrl(1, mask);
        printf("syslogd: logging ENABLED (mask=0x%x)\n", mask);
    }
    else {
        print_usage();
    }

    return 0;
}
