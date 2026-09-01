#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_null_dereference(int condition_code) {
    int *target_pointer = NULL;
    if (condition_code == 0x41) { // 'A'
        // VULNERABILITY: Dereferencing uninitialized NULL pointer
        *target_pointer = 0x1337;
        printf("Assigned value: %d\n", *target_pointer);
    } else {
        printf("Safe branch executed.\n");
    }
}

int main(int argc, char **argv) {
    char input_char = 0;
    if (read(0, &input_char, 1) > 0) {
        vulnerable_null_dereference((int)input_char);
    }
    return 0;
}
