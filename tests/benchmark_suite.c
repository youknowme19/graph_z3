#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger_null_deref() {
    int *ptr = NULL;
    printf("[*] Triggering null pointer dereference...\n");
    *ptr = 0xdeadbeef;
}

void trigger_stack_overflow() {
    char buf[8];
    printf("[*] Triggering stack overflow...\n");
    char input[32];
    memset(input, 'A', 32);
    memcpy(buf, input, 32);
}

void trigger_heap_overflow() {
    char *buf = (char *)malloc(8);
    if (!buf) return;
    printf("[*] Triggering heap overflow...\n");
    char input[32];
    memset(input, 'B', 32);
    memcpy(buf, input, 32);
    free(buf);
}

void trigger_use_after_free() {
    char *buf = (char *)malloc(16);
    if (!buf) return;
    printf("[*] Freeing buffer...\n");
    free(buf);
    printf("[*] Dereferencing freed buffer (UAF)...\n");
    buf[0] = 'C';
}

void trigger_double_free() {
    char *buf = (char *)malloc(16);
    if (!buf) return;
    printf("[*] Freeing buffer once...\n");
    free(buf);
    printf("[*] Freeing buffer twice (double free)...\n");
    free(buf);
}

int main(int argc, char **argv) {
    char action[16];
    printf("Enter test case: ");
    fflush(stdout);
    if (fgets(action, sizeof(action), stdin) == NULL) {
        return 1;
    }
    
    // Remove newline if present
    action[strcspn(action, "\n")] = 0;
    
    if (strcmp(action, "null") == 0) {
        trigger_null_deref();
    } else if (strcmp(action, "stack") == 0) {
        trigger_stack_overflow();
    } else if (strcmp(action, "heap") == 0) {
        trigger_heap_overflow();
    } else if (strcmp(action, "uaf") == 0) {
        trigger_use_after_free();
    } else if (strcmp(action, "double") == 0) {
        trigger_double_free();
    } else {
        printf("Unknown test case.\n");
    }
    return 0;
}
