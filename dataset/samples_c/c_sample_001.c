#include <string.h>
void copy_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // VULN: no bounds check
}
