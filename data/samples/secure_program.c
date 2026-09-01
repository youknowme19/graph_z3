#include <stdio.h>
#include <string.h>
#include <unistd.h>

void secure_bounded_copy(const char *input, size_t len) {
    char local_buffer[64];
    if (len >= sizeof(local_buffer)) {
        printf("Error: Input exceeds safe buffer size\n");
        return;
    }
    // SECURE: Bounded copy with explicit null termination
    strncpy(local_buffer, input, sizeof(local_buffer) - 1);
    local_buffer[sizeof(local_buffer) - 1] = '\0';
    printf("Safe buffer: %s\n", local_buffer);
}

int main(int argc, char **argv) {
    char input_buf[128] = {0};
    ssize_t bytes_read = read(0, input_buf, sizeof(input_buf) - 1);
    if (bytes_read > 0) {
        input_buf[bytes_read] = '\0';
        secure_bounded_copy(input_buf, (size_t)bytes_read);
    }
    return 0;
}
