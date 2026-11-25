/*
 * sleep_ns.c — Machine.sleep for the TZ build, veneer-backed.
 *
 * The stock sleep entry points (picoruby-machine ports/rp2040/machine.c:
 * Machine_sleep_timer / Machine_sleep_gpio over machine_sleep_run) drive
 * pico_low_power, which narrows CLOCKS sleep_en, switches the clock tree
 * and programs POWMAN — CLOCKS/PLL/XOSC/ROSC/POWMAN are all Secure-only
 * under the partition, so every cell of the stock mode x wake-source
 * matrix would BusFault from NS. Wrap both entry points (same --wrap
 * mechanism as rand_ns.c/flash_ns.c). What NS can offer instead:
 *
 *   timer, deep:  sg_deep_sleep(SG_SLEEP_DORMANT_FOR_SECS), which runs the
 *                 low-power recipe Secure-side and blocks until wake. The
 *                 veneer counts whole seconds, so ms must be >= 1000; the
 *                 sub-second remainder is waited out awake after the nap.
 *   timer, light: a plain blocking wait. No power saving, but the
 *                 contract (block for ms, console stays alive) holds.
 *   gpio, any:    not supported — the veneer menu has no GPIO wake state
 *                 (MACHINE_SLEEP_EUNSUPPORTED -> NotImplementedError).
 *
 * NS-side housekeeping around the deep nap mirrors the stock path: flush
 * CDC output, pause the 1 ms tick alarm (TIMER0 alarm 0, machine.c's
 * ALARM_NUM), detach USB, and afterwards put libc realtime forward by the
 * time the nap took. TIMER0 (time_us_64, so the monotonic clock and task
 * wakeups) does not advance while the clocks are down; the monitor's
 * POWMAN timer (sg_aon_*) does, so it measures the nap.
 *
 * A veneer refusal (SG_ERR_BUSY, core 1 running -> SG_ERR_NOT_PERMITTED)
 * is reported as MACHINE_SLEEP_ESTATE, like the stock path reports an SDK
 * precondition failure.
 */

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#include "pico.h"
#include "pico/stdlib.h"
#include "hardware/irq.h"
#include "hardware/timer.h"
#include "hardware/regs/intctrl.h"
#include "tusb.h"

#include "machine.h" /* picoruby-machine: machine_sleep_result_t */
#include "../include/r2p2_sg_api.h"

int mrb_hal_flush(int fd); /* machine hal (picorb_hal_flush); takes usb_mutex */

#define TICK_ALARM_NUM 0u /* machine.c ALARM_NUM */
#define TICK_PERIOD_US 1000u

/* Shortest deep nap: one veneer second. */
#define TZ_MIN_DORMANT_MS 1000u

static machine_sleep_result_t sleep_result_from_veneer(int rc) {
    switch (rc) {
    case SG_OK:            return MACHINE_SLEEP_OK;
    case SG_ERR_BAD_PARAM: return MACHINE_SLEEP_EINVAL;
    default:               return MACHINE_SLEEP_ESTATE; /* busy, core 1 running, ... */
    }
}

static machine_sleep_result_t deep_nap(uint32_t secs) {
    /* Wall clock before: libc realtime and the Secure AON timer. Only the
     * AON delta is used, so the two need not agree in absolute terms. */
    struct timeval tv_before;
    uint64_t aon_before_ms = 0;
    if (gettimeofday(&tv_before, NULL) != 0) return MACHINE_SLEEP_ESTATE;
    if (sg_aon_get_ms(&aon_before_ms) != SG_OK) return MACHINE_SLEEP_ESTATE;

    /* Flush the console through the HAL (it serializes against the USB
     * pump), give the pump a moment to drain to the host. */
    mrb_hal_flush(1);
    mrb_hal_flush(2);
    busy_wait_ms(5);

    /* Stop both sources that pend the USB pump (the 1 ms tick and
     * USBCTRL_IRQ). A pump already pending runs to completion right here,
     * before the next thread-level instruction, so TinyUSB is idle when we
     * touch it below. The tick must also stay quiet across the Secure
     * clock teardown, exactly like the stock sleep path keeps it. */
    uint alarm_irq = timer_hardware_alarm_get_irq_num(timer_hw, TICK_ALARM_NUM);
    irq_set_enabled(alarm_irq, false);
    irq_set_enabled(USBCTRL_IRQ, false);

    /* Detach from the USB bus BEFORE the veneer stops clk_usb. A device
     * that freezes mid-transaction with its pull-up still attached wedges
     * the upstream hub — device-verified 2026-07-11: one nap took down
     * every sibling device on the host's (internal) hub, twice. Dropping
     * the pull-up gives the host an orderly disconnect. */
    tud_disconnect();
    busy_wait_ms(2);

    int rc = sg_deep_sleep(SG_SLEEP_DORMANT_FOR_SECS, secs);

    /* Reattach: pull-up back on; the host re-enumerates and TinyUSB
     * rebuilds its state from the bus reset. (The controller kept power
     * through the nap; only its clock was stopped.) */
    tud_connect();

    machine_sleep_result_t result = sleep_result_from_veneer(rc);

    if (result == MACHINE_SLEEP_OK) {
        /* Put libc realtime forward by what the AON timer measured. Delta
         * based, like the stock aon_postsync: never steps time backwards. */
        uint64_t aon_after_ms = 0;
        if (sg_aon_get_ms(&aon_after_ms) != SG_OK || aon_after_ms < aon_before_ms) {
            result = MACHINE_SLEEP_ESTATE;
        } else {
            uint64_t delta_us = (aon_after_ms - aon_before_ms) * 1000u;
            uint64_t now_us = (uint64_t)tv_before.tv_sec * 1000000u
                            + (uint64_t)tv_before.tv_usec + delta_us;
            struct timeval tv_after;
            tv_after.tv_sec = (time_t)(now_us / 1000000u);
            tv_after.tv_usec = (suseconds_t)(now_us % 1000000u);
            if (settimeofday(&tv_after, NULL) != 0) result = MACHINE_SLEEP_ESTATE;
        }
    }

    /* Deterministic tick re-arm, as the stock path does: fresh target,
     * cleared pending, then enable. Then let USB interrupts back in. */
    timer_hw->alarm[TICK_ALARM_NUM] = timer_hw->timerawl + TICK_PERIOD_US;
    hw_clear_bits(&timer_hw->intr, 1u << TICK_ALARM_NUM);
    irq_set_enabled(alarm_irq, true);
    irq_set_enabled(USBCTRL_IRQ, true);

    return result;
}

machine_sleep_result_t __wrap_Machine_sleep_timer(bool deep, uint32_t ms) {
    if (!deep) {
        sleep_ms(ms);
        return MACHINE_SLEEP_OK;
    }
    if (ms < TZ_MIN_DORMANT_MS) return MACHINE_SLEEP_EINVAL;
    uint32_t secs = ms / 1000u;
    uint32_t rest_ms = ms % 1000u;
    if (secs > SG_SLEEP_MAX_SECS) return MACHINE_SLEEP_EINVAL;

    machine_sleep_result_t result = deep_nap(secs);
    if (result == MACHINE_SLEEP_OK && rest_ms != 0) {
        sleep_ms(rest_ms);
    }
    return result;
}

machine_sleep_result_t __wrap_Machine_sleep_gpio(bool deep, int pin, bool edge, bool high) {
    (void)deep;
    (void)pin;
    (void)edge;
    (void)high;
    return MACHINE_SLEEP_EUNSUPPORTED;
}
