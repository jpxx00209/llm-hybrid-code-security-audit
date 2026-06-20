#include <stdio.h>
void set_flag(int idx) {
    int flags[5] = {0};
    if (idx >= 0 && idx < 5) {
        flags[idx] = 1;
    }
}
