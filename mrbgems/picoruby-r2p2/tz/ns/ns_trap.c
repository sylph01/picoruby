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
 *   - then bits [19:8] of the return address, MSB first, as binary:
 *       long pulse = 1, short pulse = 0, in 3 nibble-groups (gap between).
 *   These 3 nibbles uniquely identify the caller among the abort() sites.
 *
 * Wired via --wrap=abort,--wrap=exit in ns_build.cmake. TEMPORARY.
 */
#include <stdint.h>
#include "hardware/gpio.h"

static void t_busy(uint32_t loops) {
  for (volatile uint32_t i = 0; i < loops; i++) __asm volatile ("nop");
}
#define T_MS(n) ((n) * 25000u)  /* ~n ms at 150 MHz */

/* marker = 2:abort 3:exit 4:panic 5:__assert_func 6:hard_assertion_failure
 * Blinks 3 nibbles [hibit : hibit-11] of ra, MSB first (long=1, short=0). */
static void __attribute__((noreturn)) report(uint32_t ra, int marker, int hibit) {
  gpio_init(25); gpio_set_dir(25, GPIO_OUT);
  for (;;) {
    for (int i = 0; i < marker; i++) {
      gpio_put(25, 1); t_busy(T_MS(900));
      gpio_put(25, 0); t_busy(T_MS(450));
    }
    t_busy(T_MS(1800));
    for (int b = hibit; b >= hibit - 11; b--) {
      gpio_put(25, 1); t_busy(((ra >> b) & 1u) ? T_MS(650) : T_MS(150));
      gpio_put(25, 0); t_busy(T_MS(450));
      if ((b & 3) == 0) t_busy(T_MS(1200)); /* gap between nibbles */
    }
    t_busy(T_MS(4000)); /* long gap before repeating */
  }
}

void __attribute__((noreturn)) __wrap_abort(void) {
  report((uint32_t)__builtin_return_address(0), 2, 19);
}

void __attribute__((noreturn)) __wrap_exit(int status) {
  (void)status;
  report((uint32_t)__builtin_return_address(0), 3, 19);
}

void __attribute__((noreturn)) __wrap_panic(const char *fmt, ...) {
  (void)fmt;
  report((uint32_t)__builtin_return_address(0), 4, 19);
}

void __attribute__((noreturn))
__wrap___assert_func(const char *file, int line, const char *func, const char *expr) {
  (void)file; (void)line; (void)func; (void)expr;
  report((uint32_t)__builtin_return_address(0), 5, 19);
}

/* hard_assert() (SDK) funnels here; its caller is the actual assert site.
 * Blink the caller's low 12 bits [11:0] — distinct across all sites. */
void __attribute__((noreturn)) __wrap_hard_assertion_failure(void) {
  report((uint32_t)__builtin_return_address(0), 6, 11);
}
