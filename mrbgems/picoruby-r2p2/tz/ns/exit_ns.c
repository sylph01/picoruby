/*
 * exit_ns.c — Non-secure _exit override (strong def beats the SDK's weak
 * one). Reached when C-level abort()/exit() fires inside the VM, e.g. an
 * mruby error escalating past the scheduler.
 *
 * Behavior: best-effort one-shot report of any pending mruby exception
 * over the already-running USB CDC console, then quiesce USB and halt on
 * a breakpoint. With the Debug Probe attached the bkpt stops the core
 * right here (backtrace available); without a debugger it escalates to
 * the monitor's Secure HardFault handler, which fills the tz_diag record
 * at 0x20080000 (pc = this loop) and parks the core — either way the
 * post-mortem is one SWD read away. See tz/tools/PROBE.md.
 */

#include <string.h>
#include "hardware/irq.h"
#include "mruby.h"

extern mrb_state *global_mrb;
int mrb_hal_write(int fd, const void *buf, int nbytes); /* machine hal */

static void ns_out(const char *s) {
    mrb_hal_write(2, s, (int)strlen(s));
}

static void ns_busy(uint32_t loops) {
    for (volatile uint32_t i = 0; i < loops; i++) __asm volatile ("nop");
}

void __attribute__((noreturn)) _exit(int status) {
    (void)status;
    /* USB is still IRQ-serviced at this point; write while it lives, then
     * give the host ~200 ms to drain the endpoint before quiescing. */
    ns_out("\r\nR2P2-TZ: _exit reached");
    if (global_mrb && global_mrb->exc) {
        ns_out(" — pending exception: ");
        ns_out(mrb_obj_classname(global_mrb,
                                 mrb_obj_value(global_mrb->exc)));
    }
    ns_out("\r\n(core halting; attach probe / read tz_diag @0x20080000)\r\n");
    ns_busy(5000000u);
    irq_set_enabled(USBCTRL_IRQ, false);
    for (;;) {
        __asm volatile ("bkpt 0");
        __asm volatile ("wfi");
    }
}
