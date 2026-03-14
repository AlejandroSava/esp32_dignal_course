#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

struct node {
    int data;
    struct node *prev;
    struct node *next;
};

void add_last(struct node **head, int value) {
    struct node *new_node = malloc(sizeof(struct node));
    if (new_node == NULL) {
        printf("malloc failed\n");
        return;
    }

    new_node->data = value;
    new_node->next = NULL;

    /* Case 1: empty list */
    if (*head == NULL) {
        new_node->prev = NULL;
        *head = new_node;
        return;
    }

    /* Case 2: non-empty list */
    struct node *last = *head;
    while (last->next != NULL) {
        last = last->next;
    }

    last->next = new_node;
    new_node->prev = last;
}

void add_first(struct node **head, int value) {
    struct node *new_node = (struct node *)malloc(sizeof(struct node));
    if (new_node == NULL) {
        printf("malloc failed\n");
        return;
    }

    new_node->data = value;
    new_node->prev = NULL;
    new_node->next = *head;

    if (*head != NULL) { // if there is more elements in the list
        (*head)->prev = new_node;
    }

    *head = new_node;
}

void print_list(struct node *head) {
    int count = 0;
    for (struct node *it = head; it != NULL; it = it->next) {
        printf("The list number is: %d, the value is: %d\n", count, it->data);
        count++;
    }
}

void free_list(struct node *head) {
    while (head != NULL) {
        struct node *next = head->next;
        free(head);
        head = next;
    }
}

bool find_node_value(struct node *head, int value){   
    struct node *temp = head;
    while(temp->next != NULL){
        if (temp->data == value)
            return true;
        temp = temp->next;
    }

    return false; 
    
}

void erase_node_value(struct node **head, int value){
    // the next function tries to delete the value node

    if (*head == NULL ){
        printf("The List is empty, nothing to delete\n");
        return;
    }
    
    struct node *temp = *head;
    //0 . Find the value 
    while(temp != NULL && temp->data != value){
        temp = temp->next;
    }
    // 1. The value is not found
    if(temp == NULL){
        printf("Value not found ");
        return;
    }

    // 2. The value is in the head
    else if (temp == *head){
        *head = (*head)->next;
        (*head)->prev = NULL;
        free(temp);
        return;
    }

    // 3. The value is the latest

    else if(temp->next == NULL){
        temp->prev->next = NULL;
        free(temp);
        return;
    }

    // 4. The node is in the middle

    else {

        temp->prev->next = temp->next;
        temp->next->prev = temp->prev;
        free(temp);
        return;
    }

}

void app_main(void) {
    struct node *head = NULL;
    printf("---- CREATING LIST ELEMENTS TO last -----\n");
    for (int i = 20; i < 25; i++) {
        add_last(&head, i);
    }

    printf("---- CREATING LIST ELEMENTS TO FIRST -----\n");
    for (int i = 0; i < 11; i++) {
        add_first(&head, i);
    }

    print_list(head);
    printf("find the value of %d: %s \n", 5, find_node_value(head, 5) ? "true" : "false");
    printf("find the value of %d: %s \n", 30, find_node_value(head, 30) ? "true" : "false");
    erase_node_value(&head, 10);
    erase_node_value(&head, 20);
    printf("\n");
    print_list(head);
    free_list(head);
}
