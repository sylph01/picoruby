/*
 * ns_trap.c — capture WHO calls abort()/exit() during NS bring-up.
 *
 * The boot ends in a raw C-level abort()/exit() (LED count N=14: _exit with
 * no pending mruby exception, and mrb_protect_error around the scheduler did
 * NOT catch it, so it's not a Ruby raise). We can't read USB CDC, so wrap
 * abort()/exit() and blink the caller's return address over the LED.
 *
 * Pattern (repeats):
 *   - MARKER: 2 long pulses = abort(), 3 long pulses = exit()
 *   - then the low 20 bits of the return address, MSB first, as binary:
 *       long pulse = 1, short pulse = 0, in 5 nibble-groups (gap between).
 *   Reconstruct the address as 0x10000000 | <20 bits>, then addr2line.
 *
 * Wired via --wrap=abort,--wrap=exit in ns_build.cmake. TEMPORARY.
 */
#include <stdint.h>
#include "hardware/gpio.h"

static void t_busy(uint32_t loops) {
  for (volatile uint32_t i = 0; i < loops; i++) __asm volatile ("nop");
}
#define T_MS(n) ((n) * 25000u)  /* ~n ms at 150 MHz */

static void __attribute__((noreturn)) report(uint32_t ra, int is_exit) {
  gpio_init(25); gpio_set_dir(25, GPIO_OUT);
  for (;;) {
    /* marker */
    for (int i = 0; i < (is_exit ? 3 : 2); i++) {
      gpio_put(25, 1); t_busy(T_MS(900));
      gpio_put(25, 0); t_busy(T_MS(450));
    }
    t_busy(T_MS(1800));
    /* low 20 bits, MSB first: long=1, short=0 */
    for (int b = 19; b >= 0; b--) {
      gpio_put(25, 1); t_busy(((ra >> b) & 1u) ? T_MS(650) : T_MS(150));
      gpio_put(25, 0); t_busy(T_MS(450));
      if ((b & 3) == 0) t_busy(T_MS(1200)); /* gap between nibbles */
    }
    t_busy(T_MS(4000)); /* long gap before repeating */
  }
}

void __attribute__((noreturn)) __wrap_abort(void) {
  report((uint32_t)__builtin_return_address(0), 0);
}

void __attribute__((noreturn)) __wrap_exit(int status) {
  (void)status;
  report((uint32_t)__builtin_return_address(0), 1);
}
