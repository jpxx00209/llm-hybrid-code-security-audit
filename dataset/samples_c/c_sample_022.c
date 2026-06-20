// Variant 2
#include <stdlib.h>
#include <stdio.h>
void uaf_example() {
    char *msg = malloc(20);
    free(msg);
    printf("%s", msg);  // VULN: use after free
}
