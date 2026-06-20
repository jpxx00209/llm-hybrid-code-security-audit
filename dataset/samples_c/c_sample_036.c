// Variant 3
#include <stdlib.h>
void cleanup(char *p) {
    free(p);
    free(p);  // VULN: double free
}
