// Variant 3
#include <stdlib.h>
void run_cmd(char *user_input) {
    system(user_input);  // VULN: command injection
}
