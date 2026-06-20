#include <stdlib.h>
#include <stdio.h>
void uaf_example() {
    char *msg = malloc(20);
    if (msg != NULL) {
        snprintf(msg, 20, "Hello");
        printf("%s", msg);
        free(msg);
        msg = NULL;
    }
}
