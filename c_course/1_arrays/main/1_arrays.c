#include <stdio.h>
#define POSITION 3
#define CAPACITY 7
int size = 6;
int arr[CAPACITY] = {10, 2, 7, 25, 78, 31};

void app_main(void)
{
    size++;

    for (int idx = size-1; idx > POSITION; idx--) {
        arr[idx] = arr[idx - 1];
    }

    arr[POSITION] = 50;
    

    for (int idx = 0; idx < size; idx++)
        printf("idx %d: %d\n", idx, arr[idx]);
}

