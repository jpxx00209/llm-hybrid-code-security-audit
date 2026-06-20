#include <stdio.h>
void set_flag(int idx) {
    int flags[5] = {0};
    flags[idx] = 1;  // VULN: idx unchecked
}
