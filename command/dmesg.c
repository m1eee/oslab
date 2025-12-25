#include "stdio.h"
#include "string.h" // For strlen and potentially other string ops

#define DMESG_BUF_SIZE 4096 // A reasonable buffer size for reading parts of the log
#define MAX_LINES 1000 // Max number of lines to hold in memory, for very large logs

int main(int argc, char * argv[])
{
    if (argc < 2) {
        printf("Usage: dmesg <number>\n");
        return 1;
    }

    int num_to_display = atoi(argv[1]);
    if (num_to_display <= 0) {
        printf("dmesg: <number> must be a positive integer.\n");
        return 1;
    }

    int fd = open("/syslog", O_RDWR); // Using O_RDWR as O_RDONLY is not defined
    if (fd == -1) {
        printf("dmesg: Failed to open /syslog.\n");
        return 1;
    }

    char buf[DMESG_BUF_SIZE];
    char lines_buffer[MAX_LINES][256]; // A simple array to store lines
    int current_line = 0;
    int total_bytes_read = 0;

    int n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        total_bytes_read += n;
        // This simple approach stores lines from the beginning, which might overwrite
        // older lines if MAX_LINES is reached. For "last N lines", we need more
        // sophisticated logic, like a circular buffer or a two-pass read.
        // For now, let's just count lines and then implement the two-pass logic.
    }

    // Two-pass approach:
    // Pass 1: Count total lines and determine start position
    lseek(fd, 0, SEEK_SET); // Rewind to beginning
    int total_lines = 0;
    int bytes_read_for_count = 0;
    char temp_char;
    while (read(fd, &temp_char, 1) > 0) {
        if (temp_char == '\n') {
            total_lines++;
        }
        bytes_read_for_count++;
    }
    if (bytes_read_for_count > 0 && temp_char != '\n') { // Account for last line not ending with newline
        total_lines++;
    }
    
    lseek(fd, 0, SEEK_SET); // Rewind again for actual printing

    int start_line_to_print = 0;
    if (total_lines > num_to_display) {
        start_line_to_print = total_lines - num_to_display;
    }

    int line_count = 0;
    char line_buf[256]; // Buffer for a single line
    int line_buf_idx = 0;

    while (read(fd, &temp_char, 1) > 0) {
        if (temp_char == '\n') {
            if (line_count >= start_line_to_print) {
                line_buf[line_buf_idx] = '\0'; // Null-terminate the line
                printf("%s\n", line_buf);
            }
            line_count++;
            line_buf_idx = 0; // Reset for next line
            memset(line_buf, 0, sizeof(line_buf)); // Clear buffer
        } else {
            if (line_buf_idx < sizeof(line_buf) - 1) { // Prevent buffer overflow
                line_buf[line_buf_idx++] = temp_char;
            }
        }
    }
    // Handle the very last line if it doesn't end with a newline
    if (line_buf_idx > 0 && line_count >= start_line_to_print) {
        line_buf[line_buf_idx] = '\0';
        printf("%s\n", line_buf);
    }


    close(fd);
    return 0;
}
