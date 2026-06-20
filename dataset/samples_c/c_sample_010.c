#include <stdio.h>
void log_msg(char *msg) {
    printf(msg);  // VULN: format string injection
}
