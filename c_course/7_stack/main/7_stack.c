#include <stdio.h>
#define SIZE 5

struct node{
    int data;
    struct node *next;
};


void push(int *stack, int *top, int value)
{
    if(*top == SIZE -1)
        printf("The stack is FULL\n");
    else {
        *top += 1;
        stack[*top] = value;
    }
        
}

void pop(int *stack, int *top)
{
    if(*top == -1)
        printf("The stack is empty\n");
    else 
        *top -= 1;        
}

void print_stack(int *stack, int top)
{
    for(int i = 0; i <= top; i++){
        printf("%d\n", stack[i]);
    }
}

struct node *create_node(int value){
    struct node *new_node = malloc(sizeof(struct node));
    new_node->data = value;
    new_node->next = NULL;
    return new_node;
}

void push_node(struct node **top, int value){
    if (*top == NULL){
        printf("The node is empty\n");
    }

    struct node *new_node = create_node(value);
    new_node->next = *top;
    *top = new_node;

}

void pop_node(struct node **top){
    if (*top == NULL){
        printf("The node is empty\n");
        return;
    }

    struct node *temp = *top;
    *top = (*top)->next;
    free(temp);

}

void print_stack_node(struct node *top){
    struct node *new_node = top;
    while(new_node->next != NULL){
        printf("Node Value: %d\n", new_node->data);
        new_node= new_node->next;
    }
}


void app_main(void)
{
    int stack_arr[SIZE];
    int top = -1;

    for (int i = 0; i < 5; i++){
        push(stack_arr, &top, i);
    }

    pop(stack_arr, &top);
    pop(stack_arr, &top);
    print_stack(stack_arr, top);

    struct node *top_node = NULL;
    for (int i = 0; i < 10; i++){
        push_node(&top_node, i);
    }
    print_stack_node(top_node);
    for (int i = 0; i < 3; i++){
        pop_node(&top_node);
    }
    printf("After POP\n");
    print_stack_node(top_node);

}
