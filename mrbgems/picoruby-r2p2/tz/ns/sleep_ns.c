/*
 * sleep_ns.c — Machine.sleep for the TZ build, veneer-backed.
 *
 * The stock RP2350 Machine_sleep (picoruby-machine ports/rp2040/machine.c)
 * dials VREG, switches the clock tree to LPOSC and goes dormant on a
 * POWMAN alarm — CLOCKS/PLL/XOSC/ROSC/POWMAN are all Secure-only under the
 * partition, so every step would BusFault from NS. Wrap it (same --wrap
 * mechanism as rand_ns.c/flash_ns.c) onto sg_deep_sleep, which runs the
 * identical pico-extras recipe Secure-side and blocks until wake.
 *
 * NS-side housekeeping mirrors the stock path: flush CDC output and pause
 * the 1 ms tick alarm (TIMER0 alarm 0, machine.c's ALARM_NUM) around the
 * nap. As with stock, USB drops off the bus while clk_usb is stopped and
 * the host re-enumerates after wake; TIMER0 (time_us_64, so Ruby-visible
 * monotonic time and task wakeups) does not advance while dormant, but
 * the wall clock (Machine.get_hwclock / Time) does — the monitor's POWMAN
 * timer keeps counting.
 *
 * On any veneer refusal (SG_ERR_BUSY, core 1 running → NOT_PERMITTED,
 * out-of-menu argument) fall back to a plain timed sleep so Machine.sleep
 * keeps its contract, just without the power saving.
 */

#include <stdio.h>

#include "pico.h"
#include "pico/stdlib.h"
#include "hardware/irq.h"
#include "hardware/timer.h"
#include "hardware/regs/intctrl.h"
#include "tusb.h"

#include "../include/r2p2_sg_api.h"

void __wrap_Machine_sleep(uint32_t seconds) {
    if (seconds == 0) return;

    /* Detach from the USB bus BEFORE the veneer stops clk_usb. A device
     * that freezes mid-transaction with its pull-up still attached wedges
     * the upstream hub — device-verified 2026-07-11: one nap took down
     * every sibling device on the host's (internal) hub, twice. Flush the
     * console, give the IRQ-driven tud_task pump a moment to drain to the
     * host, then quiesce the pump (under TZ, USBCTRL_IRQ is the ONLY
     * tud_task caller — never call it from thread context) and drop the
     * pull-up so the host sees an orderly disconnect. */
    tud_cdc_write_flush();
    busy_wait_ms(5);
    irq_set_enabled(USBCTRL_IRQ, false);
    tud_disconnect();
    busy_wait_ms(2);

    /* machine.c's tick source is TIMER0 alarm 0; keep it quiet across the
     * clock teardown, exactly like the stock sleep paths do. */
    uint alarm_irq = timer_hardware_alarm_get_irq_num(timer_hw, 0);
    irq_set_enabled(alarm_irq, false);

    int rc = sg_deep_sleep(SG_SLEEP_DORMANT_FOR_SECS, seconds);

    irq_set_enabled(alarm_irq, true);

    /* Reattach: pull-up back on, IRQ pump back; the host re-enumerates
     * and TinyUSB rebuilds its state from the bus reset. (The controller
     * kept power through dormant; only its clock was stopped.) */
    tud_connect();
    irq_set_enabled(USBCTRL_IRQ, true);

    if (rc != SG_OK) {
        /* No low-power state available (busy veneer, core 1 running, ...):
         * still honor the sleep duration. */
        sleep_ms(seconds * 1000u);
    }
}
