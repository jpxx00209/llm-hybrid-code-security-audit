#include <string.h>
void concat(char *a, char *b) {
    char buf[32];
    buf[0] = '\0';
    if (a != NULL)
        strncat(buf, a, sizeof(buf) - strlen(buf) - 1);
    if (b != NULL)
        strncat(buf, b, sizeof(buf) - strlen(buf) - 1);
}
