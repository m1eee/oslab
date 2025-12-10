#include "stdio.h"
#include "const.h"
#include "string.h"

#define PUBLIC

PUBLIC  int getklog(char * buf);

/* kernel/log.c */
PUBLIC void klog(int type, char *fmt, ...);

/* 
 * syslogd.c
 * System Log Daemon for Orange'S
 * Reads from kernel klog buffer and writes to /syslog
 */

int main(int argc, char * argv[])
{
    int fd;
    char buf[1024];
    int n;

    /* Open or Create /syslog */
    /* flags might differ in Orange'S implementation, using assumption */
    fd = open("/syslog", O_CREAT | O_RDWR);
    if (fd == -1) {
        printf("syslogd: failed to open /syslog\n");
        return 1;
    }

    /* Seek to end? Orange'S O_APPEND might not be fully implemented, 
       so let's just write. If it's a new file, it starts at 0. */

    while (1) {
        n = getklog(buf);
        if (n > 0) {
            write(fd, buf, n);
        } else {
            /* No data, sleep a bit */
            /* Orange'S standard sleep or delay? */
            /* We can use a busy wait or a dummy syscall if sleep isn't standard user lib */
            /* milli_delay is kernel. */
            /* Let's spin a bit */
            int i = 0;
            for(i=0;i<10000;i++) {}
        }
    }

    close(fd);
    return 0;
}
