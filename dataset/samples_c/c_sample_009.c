#include <stdio.h>
int sum_array(int *arr, int n) {
    int sum;
    for (int i = 0; i < n; i++) {
        sum += arr[i];  // VULN: sum uninitialized
    }
    return sum;
}
