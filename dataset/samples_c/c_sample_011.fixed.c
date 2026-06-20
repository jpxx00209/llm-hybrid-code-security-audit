#include <stdlib.h>
#include <string.h>
void run_cmd(char *user_input) {
    if (user_input == NULL) return;
    if (strpbrk(user_input, ";&|")) {
        fprintf(stderr, "Invalid characters\n");
        return;
    }
    system(user_input);
}
