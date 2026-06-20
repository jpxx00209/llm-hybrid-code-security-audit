// Variant 2 (Fixed)
#include <stdlib.h>
#include <string.h>
void heap_copy(char *src) {
    size_t len = strlen(src) + 1;
    char *dst = malloc(len);
    if (dst != NULL) {
        strncpy(dst, src, len - 1);
        dst[len - 1] = '\0';
        free(dst);
    }
}
