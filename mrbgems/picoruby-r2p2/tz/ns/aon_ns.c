/*
 * aon_ns.c — Non-secure pico_aon_timer replacement, veneer-backed.
 *
 * The RP2350 always-on timer lives in POWMAN (0x40100000), which is
 * Secure-only under the partition; direct use BusFaults from NS (confirmed
 * on target 2026-07-02). Phase 1 replaced it with a TIMER0-based software
 * clock; that couldn't survive deep sleep (TIMER0 stops) or watchdog
 * reboots. Since backlog item 3 the monitor owns the POWMAN timer
 * (started at boot, ticking through sg_deep_sleep and reboots) and exposes
 * it as sg_aon_get_ms/sg_aon_set_ms — these wraps put pico_aon_timer's
 * API on top of it. Same linker --wrap mechanism as rand_ns.c/flash_ns.c;
 * only the 4 aon_timer_* functions R2P2 actually uses are wrapped.
 *
 * Resolution is the POWMAN timer's 1 kHz: sub-ms of a set is truncated,
 * get_time reports whole milliseconds.
 */

#include "pico.h"
#include "pico/aon_timer.h"

#include "../include/r2p2_sg_api.h"

static uint64_t ts_to_ms(const struct timespec *ts) {
    return (uint64_t)ts->tv_sec * 1000u + (uint64_t)(ts->tv_nsec / 1000000L);
}

static bool aon_set(const struct timespec *ts) {
    if (!ts) return false;
    return sg_aon_set_ms(ts_to_ms(ts)) == SG_OK;
}

bool __wrap_aon_timer_start(const struct timespec *ts)    { return aon_set(ts); }
bool __wrap_aon_timer_set_time(const struct timespec *ts) { return aon_set(ts); }

bool __wrap_aon_timer_is_running(void) {
    uint64_t ms;
    return sg_aon_get_ms(&ms) == SG_OK;
}

bool __wrap_aon_timer_get_time(struct timespec *ts) {
    if (!ts) return false;
    uint64_t ms;
    if (sg_aon_get_ms(&ms) != SG_OK) return false;
    ts->tv_sec  = (time_t)(ms / 1000u);
    ts->tv_nsec = (long)(ms % 1000u) * 1000000L;
    return true;
}
