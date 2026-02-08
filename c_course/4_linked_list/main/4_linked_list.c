#include <stdio.h>
#include <stdlib.h>

struct node {
    int data;
    struct node *next;
};

void add_new_to_first(struct node **head, int value){
    if(*head == NULL)
        printf("The list is empty... adding element\n");
    
    struct node *new_node = malloc(sizeof(struct node));
    new_node->data = value;
    new_node->next = *head;

    *head = new_node;
    
}

void prints_nodes(struct node **head){
    int count = 0;
    for (struct node *init = *head; init != NULL; init = init->next){
        printf("The node is:%d, the value is: %d\n", count, init->data);
        count++;
    }

}

void prints_nodes_enhance(struct node *head){ //enhancing 
    int count = 0;
    for (struct node *init = head; init != NULL; init = init->next){
        printf("The node is:%d, the value is: %d\n", count, init->data);
        count++;
    }

}

void add_new_to_end(struct node **head, int value){
        
    struct node *new_node = malloc(sizeof(struct node));
    new_node->data = value;
    new_node->next = NULL;

    if (*head == NULL){
        printf("The list is empty... adding element\n");
        *head = new_node;
    }
    else{
        struct node *last_node = *head; 
        while(last_node->next != NULL){
            last_node = last_node->next;
        }
        last_node->next = new_node;
    }
   
}


void delete_node(struct node **head, int value){
    // There are thre cases, the value in the head or in the remaining structure
    // the value is not found
    //if is the head
    if (*head == NULL){
        printf("The list is empty... nothing to delete\n");
        return;
    }
    struct node *current = *head;
    struct node *previous= NULL;
    //1) if is the head

    if(current->data == value){
        *head = current->next;
        free(current);
        return;
    }
    //2-3) try to find in the sequence 

    while(current !=NULL && current->data != value){
        // how to advance and have a previous;
        previous = current;
        current = current->next;
    }

    // 3) value not found
    if(current == NULL){
        printf("value not found! \n");
        return;
    }
    
    // 2) not in the head
    previous->next = current->next;
    free(current);
}

void app_main(void)
{
    printf("CREATING THE HEAD, INIT\n");
    struct node *head = NULL;

    printf("ADDING TO FIRST\n");

    for(int i =0; i <20 ; i++){
        add_new_to_first(&head, i);
    }

    printf("ADDING TO END\n");
    for(int i =30; i < 35; i++){
        add_new_to_end(&head, i);
    }


    //prints_nodes(&head);
    prints_nodes_enhance(head);

    printf("deleting nodes\n");
    delete_node(&head, 10);
    delete_node(&head, 19);
    delete_node(&head, 50);
    prints_nodes_enhance(head);


}
