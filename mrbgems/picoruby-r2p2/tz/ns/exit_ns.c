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
#include <tusb.h>
#include "hardware/irq.h"
#include "hardware/gpio.h"
#include "mruby.h"
#include "hal.h"   /* picorb_hal_write -> mrb_hal_write (needs PICORB_VM_MRUBY) */

extern mrb_state *global_mrb;
extern void mrb_print_error(mrb_state *mrb);

static void emit(const char *s) { picorb_hal_write(1, s, (int)strlen(s)); }

void __attribute__((noreturn)) _exit(int status) {
    (void)status;
    /* Own USB servicing exclusively: disable the USB IRQ so its tud_task()
     * can't reenter ours (tud_task is not reentrant). */
    irq_set_enabled(USBCTRL_IRQ, false);
    gpio_init(25); gpio_set_dir(25, GPIO_OUT);
    bool dumped = false;
    uint32_t hb = 0;
    for (;;) {
        tud_task();
        /* SLOW steady blink = "in _exit keepalive" (VM aborted). Distinct
         * from the usb_irq flicker and from a static LED at the shell. */
        if (((++hb) & 0x1ffffu) == 0) { gpio_xor_mask(1u << 25); }
        if (!dumped && tud_cdc_connected()) {
            emit("\r\n[TZ] _exit reached (VM aborted mid-boot).\r\n");
            if (global_mrb && global_mrb->exc) {
                mrb_print_error(global_mrb);
            } else {
                emit("[TZ] no pending mruby exception (raw abort).\r\n");
            }
            emit("[TZ] halted; USB kept alive.\r\n");
            dumped = true;
        }
    }
}
