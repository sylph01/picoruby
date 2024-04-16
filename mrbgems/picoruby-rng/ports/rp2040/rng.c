#include "../../include/rng.h"
#include "hardware/structs/rosc.h"

uint8_t rng_random_byte(void)
{
  uint32_t random = 0;
  for (int i = 0; i < 8; i++) {
    random = (random << 1) | rosc_hw->randombit;
  }
  return (uint8_t) random;
}
