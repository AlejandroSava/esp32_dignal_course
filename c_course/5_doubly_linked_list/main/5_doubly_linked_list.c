#include <stdio.h>
#include <stdlib.h>

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

    if (*head != NULL) { // if there is more elements
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
    free_list(head);
}
