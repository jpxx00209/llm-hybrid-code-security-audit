// Variant 2 (Fixed)
#include <string.h>
void copy_input(char *input) {
    char buffer[64];
    if (input != NULL) {
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    }
}
