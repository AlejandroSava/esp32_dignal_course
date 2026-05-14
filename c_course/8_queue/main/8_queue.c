#include <stdio.h>
#define SIZE 10

struct node{
    int data;
    struct node *next;
};

void node_enqueue(struct node **head, struct node **tail, int value){
    struct node *new_node = malloc(sizeof(struct node));
    new_node->next = NULL;
    new_node->data = value;

    if (*head == NULL && *tail == NULL){
        printf("The queue is empty\n");
        *head = *tail = new_node;
    }
    else{
        (*tail)->next = new_node; 
        *tail = new_node;
    }
}

void node_dequeue(struct node **head, struct node **tail){
    if (*head == NULL && *tail == NULL){
        printf("The queue is empty\n");
        return;
    }
    struct node *aux = *head;
    *head = (*head)->next;
    if(*head == NULL)
        *tail = NULL;
    free(aux);
}

void print_node_queue(struct node **head, struct node **tail){
    struct node *temp = *head;
    if (*head == NULL && *tail == NULL){
        printf("The queue is empty\n");
    }

    while( temp != NULL){
        printf("The queue value is: %d\n", temp->data);
        temp = temp->next;
    }
}


void enqueue(int *arr, int *head, int *tail, int value)
{
    if (*tail == SIZE){
        printf("There isn't more slot in the queue\n");
    }
    arr[*tail] = value;
    *tail += 1;
}

void dequeue(int *arr, int *head, int *tail)
{
    if (*tail == *head){
        printf("There queue is empy");
    }
    *head += 1;
}


void print_pointers(int *head, int *tail){
    printf("The head is: %d\n", *head);
    printf("The tail is: %d\n", *tail);
}

void print_queue(int *arr, int *head, int *tail){
    if (*head == *tail){
        printf("The queue is empty\n");
        return;
    }
    for(int i = *head; i < *tail; i++){
        printf("The queue value is: %d \n", arr[i]);
    }
}

void app_main(void)
{
    int head = 0, tail = 0;
    int arr[SIZE];
    for (int i = 0; i < SIZE; i++){
        enqueue(&arr[0], &head, &tail, i);
    }

    print_pointers(&head, &tail);
    print_queue(&arr[0], &head, &tail);
    dequeue(&arr[0], &head, &tail);
    dequeue(&arr[0], &head, &tail);
    print_pointers(&head, &tail);
    print_queue(&arr[0], &head, &tail);

    struct node *head_list = NULL;
    struct node *tail_list = NULL;
    for (int i = 0; i < 10; i++)
        node_enqueue(&head_list, &tail_list, i);
    print_node_queue(&head_list, &tail_list);
    printf("\n");
    node_dequeue(&head_list, &tail_list);
    node_dequeue(&head_list, &tail_list);
    print_node_queue(&head_list, &tail_list);

}
