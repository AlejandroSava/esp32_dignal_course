#include <stdio.h>

#define ARR_CAPACITY 7
int search_number(int *arr, int arr_size, int find_number){
    for(int i = 0; i < arr_size; i++ ){
        if(arr[i] == find_number)
            return i;
    }
    return -1;
}

void remove_element(int *arr, int *arr_size, int index){
    for(int i = index; i < *arr_size -1 ; i++ ){
        arr[i] = arr[i+1];
        (*arr_size)--;
    }
}

void app_main(void)
{   int arr_size = 6;
    int arr[6] = {10, 2, 7, 25, 78, 31};
    int remove = 2;
    int remove_index = search_number(&arr[0], arr_size, remove);
    if (remove_index != -1){ 
        remove_element(&arr[0], &arr_size, remove_index);

        for(int i = 0; i < arr_size; i++){
            printf("Arr element %d: %d \n", i, arr[i]);
        }
    }
    else
        printf("Number not found!!!\n");
}
