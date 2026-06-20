// Variant 4
#include <stdlib.h>
#include <string.h>
void heap_copy(char *src) {
    char *dst = malloc(10);
    strcpy(dst, src);  // VULN: dst may be too small
    free(dst);
}
