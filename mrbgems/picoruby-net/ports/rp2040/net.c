#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

void
Net_sleep_ms(int ms)
{
#if PICO_CYW43_ARCH_POLL
  /* Poll mode (TZ builds): nothing services the chip/lwIP timers during
   * the sleep, so poll across the whole wait instead of once up front.
   * cyw43_arch_wait_for_work_until sleeps until driver work or deadline. */
  absolute_time_t deadline = make_timeout_time_ms(ms);
  while (!time_reached(deadline)) {
    cyw43_arch_poll();
    cyw43_arch_wait_for_work_until(deadline);
  }
#else
  cyw43_arch_poll();
  sleep_ms(ms);
#endif
}

void
lwip_begin(void)
{
  cyw43_arch_lwip_begin();
}

void
lwip_end(void)
{
  cyw43_arch_lwip_end();
}
