#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_buffer_copy(const char *input) {
    char local_buffer[32];
    // VULNERABILITY: Unbounded memory copy allows stack smashing / return address overwrite
    strcpy(local_buffer, input);
    printf("Buffer received: %s\n", local_buffer);
}

int main(int argc, char **argv) {
    char input_buf[128] = {0};
    ssize_t bytes_read = read(0, input_buf, sizeof(input_buf) - 1);
    if (bytes_read > 0) {
        input_buf[bytes_read] = '\0';
        vulnerable_buffer_copy(input_buf);
    }
    return 0;
}
