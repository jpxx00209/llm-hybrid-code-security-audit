#include <stdio.h>
int sum_array(int *arr, int n) {
    int sum = 0;
    if (arr == NULL || n <= 0) return 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}
