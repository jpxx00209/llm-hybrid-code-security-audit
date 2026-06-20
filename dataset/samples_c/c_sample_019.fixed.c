// Variant 2 (Fixed)
#include <stdio.h>
#include <limits.h>
int alloc_size(int n) {
    if (n > 0 && n > INT_MAX / sizeof(int)) {
        fprintf(stderr, "Integer overflow detected\n");
        return -1;
    }
    return n * sizeof(int);
}
