#include <stdlib.h>
void cleanup(char *p) {
    if (p != NULL) {
        free(p);
        p = NULL;
    }
}
