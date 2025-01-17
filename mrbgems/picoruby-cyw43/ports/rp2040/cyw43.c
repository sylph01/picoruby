#include "../../include/cyw43.h"

#include "pico/cyw43_arch.h"

int
CYW43_arch_init_with_country(const uint8_t *country)
{
  return cyw43_arch_init_with_country(CYW43_COUNTRY(country[0], country[1], 0));
}

void
CYW43_GPIO_write(uint8_t pin, uint8_t val)
{
  cyw43_arch_gpio_put(pin, val == 1);
}

uint8_t
CYW43_GPIO_read(uint8_t pin)
{
  return(cyw43_arch_gpio_get(pin) ? 1 : 0);
}
