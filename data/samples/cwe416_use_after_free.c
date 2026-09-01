#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct UserSession {
    int auth_level;
    char username[24];
};

void vulnerable_use_after_free(char trigger_code) {
    struct UserSession *session = (struct UserSession *)malloc(sizeof(struct UserSession));
    if (!session) return;
    session->auth_level = 1;
    strcpy(session->username, "guest_user");

    // Free the heap object
    free(session);

    // VULNERABILITY: Accessing session object after free() without null check
    if (trigger_code == 'X') {
        printf("Session auth level: %d\n", session->auth_level);
        session->auth_level = 99; // Heap write-after-free
    }
}

int main(int argc, char **argv) {
    char code = 0;
    if (read(0, &code, 1) > 0) {
        vulnerable_use_after_free(code);
    }
    return 0;
}
