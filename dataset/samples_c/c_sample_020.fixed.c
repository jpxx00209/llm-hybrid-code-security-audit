// Variant 2 (Fixed)
#include <stdio.h>
unsigned int subtract(unsigned int a, unsigned int b) {
    if (b > a) {
        fprintf(stderr, "Underflow detected\n");
        return 0;
    }
    return a - b;
}
