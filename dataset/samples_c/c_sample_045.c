// Variant 3
#include <string.h>
void concat(char *a, char *b) {
    char buf[32];
    strcat(buf, a);  // VULN: potential overflow
    strcat(buf, b);
}
