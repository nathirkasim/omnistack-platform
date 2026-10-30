#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>

void process_buffer(const char* user_input) {
    char stack_buf[64];
    // VULNERABLE: Unbounded strcpy into fixed stack buffer creates Buffer Overflow (CWE-120)
    strcpy(stack_buf, user_input);
}

void print_user_message(const char* message) {
    // VULNERABLE: User-controlled format string passed directly to printf (CWE-134)
    printf(message);
}

void run_backup(const char* filename) {
    char cmd[256];
    // VULNERABLE: Concatenating input into system command string (CWE-78)
    snprintf(cmd, sizeof(cmd), "tar -czf backup.tar.gz %s", filename);
    system(cmd);
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        process_buffer(argv[1]);
        print_user_message(argv[1]);
        run_backup(argv[1]);
    }
    return 0;
}
