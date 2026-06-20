#include <stdio.h>
#include <string.h>
void print_len(char *s) {
    if (s != NULL) {
        printf("%zu", strlen(s));
    } else {
        printf("0");
    }
}
