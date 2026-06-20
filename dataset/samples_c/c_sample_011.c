#include <stdlib.h>
#include <string.h>
void run_cmd(char *user_input) {
    system(user_input);  // VULN: command injection
}
