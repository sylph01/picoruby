/*
 * exit_ns.c — Non-secure _exit override for TZ bring-up. SKETCH / TEMPORARY.
 *
 * On the TZ split the NS image has no UART/SWD console, and the mruby VM
 * reaches _exit two ways during a failed boot:
 *   1. main() returns after mrb_task_run() (a task raised, scheduler ended)
 *      -> handled by the keepalive loop in main.c (mrb still open there).
 *   2. a C-level abort()/panic *inside* mrb_task_run -> jumps straight to
 *      _exit, bypassing that loop. The stock weak _exit just bkpt-loops,
 *      which escalates to the monitor's HardFault handler (LED nibble
 *      read-out) and the USB port never comes up.
 *
 * This strong override (beats the SDK's __weak _exit) turns case 2 into a
 * console: keep servicing TinyUSB so the CDC port enumerates, and once the
 * host attaches, print the pending mruby error via global_mrb. Remove once
 * boot is clean.
 *
 * tud_task()/tud_cdc_connected() and picorb_hal_write are macros, so we must
 * pull the real headers (bare externs referenced non-existent symbols).
 */

#include <string.h>
#include "hardware/irq.h"
#include "hardware/gpio.h"
#include "mruby.h"

extern mrb_state *global_mrb;
extern const char *mrb_obj_classname(mrb_state *mrb, mrb_value obj);

/* Report the abort cause over the LED (GPIO25) as a small countable number
 * of slow blinks — USB CDC has proven unreadable in NS bring-up, and this
 * _exit path (C-level exit inside mrb_task_run) is the one actually taken.
 * The number matches main.c's tz_blink_count table, with distinct markers
 * for the _exit path: 14 = raw abort (no pending exception). */
static void ns_busy(uint32_t loops) {
    for (volatile uint32_t i = 0; i < loops; i++) __asm volatile ("nop");
}
#define NS_MS(n) ((n) * 25000u)  /* ~n ms at 150 MHz */
static int ns_exc_index(const char *cls) {
    static const char *names[] = {
        "RuntimeError", "LoadError", "ArgumentError", "NoMethodError",   /* 2-5  */
        "NameError", "TypeError", "StandardError", "NotImplementedError",/* 6-9  */
        "IndexError", "KeyError", "RangeError", "ScriptError",           /* 10-13*/
    };
    for (int i = 0; i < 12; i++) if (strcmp(cls, names[i]) == 0) return i + 2;
    return 15; /* an exception, but not one in the table */
}
static void __attribute__((noreturn)) ns_blink_count(int n) {
    gpio_init(25); gpio_set_dir(25, GPIO_OUT);
    for (;;) {
        for (int i = 0; i < n; i++) {
            gpio_put(25, 1); ns_busy(NS_MS(300));
            gpio_put(25, 0); ns_busy(NS_MS(300));
        }
        ns_busy(NS_MS(4000));
    }
}

void __attribute__((noreturn)) _exit(int status) {
    (void)status;
    irq_set_enabled(USBCTRL_IRQ, false);
    int n;
    if (global_mrb && global_mrb->exc) {
        n = ns_exc_index(mrb_obj_classname(global_mrb, mrb_obj_value(global_mrb->exc)));
    } else {
        n = 14; /* raw C-level abort, no pending mruby exception */
    }
    ns_blink_count(n); /* never returns */
}
