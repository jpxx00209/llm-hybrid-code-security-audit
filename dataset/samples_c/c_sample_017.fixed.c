// Variant 2 (Fixed)
#include <stdio.h>
void process(int idx) {
    int arr[10];
    if (idx >= 0 && idx < 10) {
        arr[idx] = 42;
    } else {
        fprintf(stderr, "Index out of bounds\n");
    }
}
