// Variant 4
#include <stdio.h>
unsigned int subtract(unsigned int a, unsigned int b) {
    return a - b;  // VULN: underflow if b > a
}
