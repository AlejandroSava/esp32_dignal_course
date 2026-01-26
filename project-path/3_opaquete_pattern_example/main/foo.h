#ifndef FOO_H
#define FOO_H

/* Forward declaration (incomplete type) */
typedef struct foo foo_t; // foo it's a structure that is not defined yet

// remember that typedef struct node {...} node_t;
/* Public API */
foo_t *foo_create(int value); // foot_t structure to create an object
void   foo_do_something(foo_t *self);
void   foo_destroy(foo_t *self);

#endif
