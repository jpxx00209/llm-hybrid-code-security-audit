// Variant 3
#include <stdio.h>
void print_len(char *s) {
    printf("%d", strlen(s));  // VULN: s may be NULL
}
