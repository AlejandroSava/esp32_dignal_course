#include "foo.h"
#include <stdlib.h>
#include <stdio.h>

/* Real definition (hidden) */ 
struct foo {
    int value;
    int secret;
}; // definition of foo

foo_t *foo_create(int value) // foot_t is the structure foo
{
    foo_t *self = malloc(sizeof(*self));
    if (!self) return NULL;

    self->value  = value;
    self->secret = value ^ 0xAA;

    return self; // know self is a pointer pointing to foo_t that is the same that structure foo
}

void foo_do_something(foo_t *self)
{
    printf("value=%d secret=%d\n", self->value, self->secret);
}

void foo_destroy(foo_t *self)
{
    free(self);
}
