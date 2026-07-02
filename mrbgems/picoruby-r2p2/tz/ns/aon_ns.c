/*
 * aon_ns.c — Non-secure software replacement for pico_aon_timer. SKETCH.
 *
 * The RP2350 always-on timer lives in POWMAN (0x40100000), which is
 * Secure-only under the partition. R2P2 boot calls Machine.set_hwclock(0)
 * (main_task.rb) -> aon_timer_set_time/start -> POWMAN -> BusFault from NS
 * (confirmed on target 2026-07-02: fault via double-tap POWMAN read first,
 * then this at Ruby boot).
 *
 * Phase-1 fix: back the wall clock with time_us_64() (TIMER0, NS-granted,
 * ticks already started by the monitor) instead of POWMAN. Same linker
 * --wrap mechanism as rand_ns.c / flash_ns.c; only the 4 aon_timer_*
 * functions R2P2 actually uses are wrapped.
 *
 * LIMITATIONS (acceptable for bring-up, revisit later):
 *  - Does NOT survive deep sleep / RUN-pin resets the way the POWMAN AON
 *    timer would (that's the whole point of an always-on timer). For a
 *    real time-of-day that persists across low-power states, this needs a
 *    Secure veneer (sg_aon_*) so the monitor drives POWMAN.
 *  - Machine.sleep's POWMAN alarm path is separate and still Secure-only;
 *    it will fault if invoked (see tz/README.md gem table). Not exercised
 *    at boot.
 */

#include "pico.h"
#include "pico/aon_timer.h"
#include "pico/time.h"

static struct timespec s_base;   /* wall clock at s_ref_us */
static uint64_t        s_ref_us; /* TIMER0 timestamp when s_base was set */
static bool            s_running;

static bool aon_set(const struct timespec *ts) {
    if (!ts) return false;
    s_base = *ts;
    s_ref_us = time_us_64();
    s_running = true;
    return true;
}

bool __wrap_aon_timer_start(const struct timespec *ts)    { return aon_set(ts); }
bool __wrap_aon_timer_set_time(const struct timespec *ts) { return aon_set(ts); }
bool __wrap_aon_timer_is_running(void)                    { return s_running; }

bool __wrap_aon_timer_get_time(struct timespec *ts) {
    if (!ts || !s_running) return false;
    uint64_t elapsed = time_us_64() - s_ref_us;
    ts->tv_sec  = s_base.tv_sec + (time_t)(elapsed / 1000000u);
    long nsec   = s_base.tv_nsec + (long)((elapsed % 1000000u) * 1000u);
    if (nsec >= 1000000000L) { ts->tv_sec += 1; nsec -= 1000000000L; }
    ts->tv_nsec = nsec;
    return true;
}
