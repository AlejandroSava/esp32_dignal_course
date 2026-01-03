#include "foo.h"


void app_main(void)
{
    foo_t *pt_foot_t = foo_create(42);

    foo_do_something(pt_foot_t);
    // you are not able to access to the struture foo filds, they are not kwnon in this section
    // the only way to access is by methods, like an API

    foo_destroy(pt_foot_t);
    
}
