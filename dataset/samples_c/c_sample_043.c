// Variant 3
#include <stdio.h>
void write_data(int len) {
    char buf[100];
    if (len < 100)
        memcpy(buf, "data", len);  // VULN: len is signed, negative bypasses check
}
