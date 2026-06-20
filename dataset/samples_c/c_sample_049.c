// Variant 4
#include <stdio.h>
int alloc_size(int n) {
    return n * sizeof(int);  // VULN: integer overflow possible
}
