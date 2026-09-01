#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vulnerable_format_string(const char *user_format) {
    // VULNERABILITY: Directly passing user controlled string as format specifier
    printf(user_format);
    printf("\n");
}

int main(int argc, char **argv) {
    char format_buf[64] = {0};
    ssize_t bytes_read = read(0, format_buf, sizeof(format_buf) - 1);
    if (bytes_read > 0) {
        format_buf[bytes_read] = '\0';
        vulnerable_format_string(format_buf);
    }
    return 0;
}
