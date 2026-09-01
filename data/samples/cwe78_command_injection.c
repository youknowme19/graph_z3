#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vulnerable_command_execution(const char *user_argument) {
    char system_command[128];
    // VULNERABILITY: User input formatted directly into system() shell execution
    snprintf(system_command, sizeof(system_command), "echo 'Processing: %s'", user_argument);
    system(system_command);
}

int main(int argc, char **argv) {
    char input_buffer[64] = {0};
    ssize_t bytes_read = read(0, input_buffer, sizeof(input_buffer) - 1);
    if (bytes_read > 0) {
        input_buffer[bytes_read] = '\0';
        vulnerable_command_execution(input_buffer);
    }
    return 0;
}
