/*
 * flash_ns.c — link-level replacement for hardware_flash's flash_range_erase
 * / flash_range_program in the Non-secure R2P2 image, backed by the Secure
 * flash veneers (sg_flash_erase / sg_flash_program). SKETCH.
 *
 * Why a Secure veneer instead of calling the bootrom from NS:
 *   - The SDK's flash path (flash_safe_execute) acquires a lock word in
 *     BOOTRAM (0x400e0000), which is Secure-only and bus-faults from NS.
 *   - Calling the bootrom checked flash op ('FO') directly from NS avoids
 *     the lock, but that ROM function leaves flash/XIP unreadable across the
 *     call (it does not re-enter XIP for the caller). The NS caller's next
 *     instruction fetch is then from dead flash and the core locks up
 *     (confirmed on target 2026-07-02: hang inside the ROM op, even with
 *     interrupts masked).
 *
 * So flash writes go through the monitor: flash_range_erase/program there are
 * RAM-resident and manage XIP exit/re-enter + cache flush, and Secure code
 * may hold the BOOTRAM lock. The veneers also clamp every op to the NS
 * filesystem partition, so NS can't erase/program the monitor or NS code.
 *
 * Link mechanics: hardware_flash is an SDK INTERFACE library whose flash.c is
 * injected as a peer object, so we use --wrap (ns_build.cmake) to redirect
 * flash_range_erase/flash_range_program to the __wrap_* versions below. This
 * transitively fixes picoruby-filesystem-fat and picoruby-littlefs.
 */

#include "pico.h"

#include "../include/r2p2_sg_api.h"

/* A failed Secure flash veneer is an invariant break (the monitor's range
 * clamp or buffer validation rejected a FatFS request) — never continue
 * silently. The failing op and rc are parked in globals for the probe,
 * then bkpt: with a debugger attached the core halts right here;
 * unattended it escalates to the monitor's HardFault handler and lands in
 * the tz_diag record (pc = this loop). See tz/tools/PROBE.md. */
volatile int ns_flash_trap_op;  /* 'E'rase / 'P'rogram */
volatile int ns_flash_trap_rc;  /* sg_status_t */

static void __attribute__((noreturn)) ns_flash_trap(int op, int rc) {
    ns_flash_trap_op = op;
    ns_flash_trap_rc = rc;
    for (;;) {
        __asm volatile ("bkpt 0");
        __asm volatile ("wfi");
    }
}

void __wrap_flash_range_erase(uint32_t flash_offs, size_t count) {
    int rc = sg_flash_erase(flash_offs, (uint32_t)count);
    if (rc != SG_OK) ns_flash_trap('E', rc);
}

void __wrap_flash_range_program(uint32_t flash_offs, const uint8_t *data, size_t count) {
    int rc = sg_flash_program(flash_offs, data, (uint32_t)count);
    if (rc != SG_OK) ns_flash_trap('P', rc);
}
