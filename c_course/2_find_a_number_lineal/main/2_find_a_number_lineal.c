#include <stdio.h>
#define ARR_SIZE 7
int search_number(int *arr, int arr_size, int find_number){
    for(int i = 0; i < arr_size; i++ ){
        if(arr[i] == find_number)
            return i;
    }
    return -1;
}

void app_main(void)
{
    int arr[ARR_SIZE] = {10, 2, 7, 25, 78, 31, 50};
    int find_number = 31;

    int number_found = search_number(&arr[0], ARR_SIZE, find_number);
    if (number_found == -1)
        printf("The number is not in the array");
    else
        printf("The number appears in the array. Index: %d, number %d\n",number_found, arr[number_found] );

}
