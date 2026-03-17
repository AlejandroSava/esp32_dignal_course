#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

struct nodo {
    int data;
    struct nodo * next;
};

void add_first(struct nodo **head, int value){

    struct nodo *new_nodo = malloc(sizeof(struct nodo));
    new_nodo->data = value;

    if(*head == NULL){ // when there isn't any element
        new_nodo->next = new_nodo;
        *head = new_nodo;
    }
    else{ // when the list is not empty 
        struct nodo *temp = *head;
        while(temp->next != *head){
            temp = temp->next;
        }

        temp->next = new_nodo;
        new_nodo->next = *head;
        *head = new_nodo;
    }
}

void add_end(struct nodo **head, int value){
    // the only change with add_first is where head points
    struct nodo *new_nodo = malloc(sizeof(struct nodo));
    new_nodo->data = value;

    if(*head == NULL){ // when there isn't any element
        new_nodo->next = new_nodo;
        *head = new_nodo;
    }
    else{ // when the list is not empty 
        struct nodo *temp = *head;
        while(temp->next != *head){
            temp = temp->next;
        }

        temp->next = new_nodo;
        new_nodo->next = *head;        
    }
}

bool find_value(struct nodo *head, int value){
    if(head == NULL)
        return false;

    struct nodo *temp = head;
    do {
        if(temp->data == value)
            return true;
        
        temp = temp->next;
    } while (temp != head);
    return false;
}

void delete_node(struct nodo **head, int value)
{
    /* There are 3 scenarios:
       1. delete head
       2. delete node in the middle
       3. delete the only node available
    */
    if (*head == NULL)
        return;

    struct nodo *current = *head;
    struct nodo *prev = NULL;

    /* Scenario 3: only one node */
    if (current->next == *head && current->data == value) {
        free(current);
        *head = NULL;
        return;
    }

    /* Find the node to delete */
    do {
        prev = current;
        current = current->next;

        if (current->data == value)
            break;

    } while (current != *head);

    /* Value not found */
    if (current->data != value)
        return;

    /* If the node is head */
    if (current == *head) {
        *head = current->next;
        prev->next = *head;
        free(current);
    } else {
        prev->next = current->next;
        free(current);
    }
}

void print_list(struct nodo * head){
    struct nodo *ini = head;
    do {
        printf("The data value is: %d\n", ini->data);
        ini = ini->next;
    } while (ini != head);
}

void app_main(void){
    struct nodo *head = NULL;
    for(int i = 0; i < 15; i++){
        add_first(&head, i);
    }
    for(int i = 25; i < 40; i++){
        add_end(&head, i);
    }

    print_list(head);
    for(int i = 15; i < 35; i++){
        printf("find the value %d: %s\n", i, find_value(head,i) ? "true" : "false");
    }
    delete_node(&head, 14);
    delete_node(&head, 39);
    delete_node(&head, 10);
    print_list(head);
}


void example(void){
    struct node
    {
        int data;
        struct node *next;
    };

    struct node *head, *middle, *last;
    
    head   = malloc(sizeof(struct node));
    middle = malloc(sizeof(struct node));
    last   = malloc(sizeof(struct node));

    head->data   = 100;
    middle->data = 200;
    last->data   = 300;

    //Implemente la tarea 1 aquí: 
    //Cree la siguiente lista circular enlazada conectando los nodos. head->middle->last->head
    head->next = middle;
    middle->next = last;
    last->next = head;
    
    // Implemente la tarea 2 aquí:
    // Imprima la lista circular enlazada creada. es decir, el resultado esperado es 100 200 300.
    // Print circular linked list once: 100 200 300
    struct node *ini = head;
    do {
        printf("The data value is: %d\n", ini->data);
        ini = ini->next;
    } while (ini != head);
}