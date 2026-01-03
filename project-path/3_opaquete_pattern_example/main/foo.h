#ifndef FOO_H
#define FOO_H

/* Forward declaration (incomplete type) */
typedef struct foo foo_t;

/* Public API */
foo_t *foo_create(int value);
void   foo_do_something(foo_t *f);
void   foo_destroy(foo_t *f);

#endif
