#include <stdio.h>
#include <string.h>
void write_data(int len) {
    char buf[100];
    if (len > 0 && len < 100)
        memcpy(buf, "data", len);
}
