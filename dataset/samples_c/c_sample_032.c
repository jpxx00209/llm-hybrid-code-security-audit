// Variant 3
#include <stdio.h>
void process(int idx) {
    int arr[10];
    arr[idx] = 42;  // VULN: idx unchecked
}
