#include <mrubyc.h>
#include <alloc.h>

#include "../include/rng.h"

static void
c_rng_random_byte(mrbc_vm *vm, mrbc_value *v, int argc)
{
  SET_INT_RETURN(rng_random_byte());
}

void
mrbc_rng_init(void)
{
  mrbc_class *class_RNG = mrbc_define_class(0, "RNG", mrbc_class_object);

  mrbc_define_method(0, class_RNG, "random_byte", c_rng_random_byte);
}
