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

/* TEMP bring-up: on error blink the veneer rc instead of failing silently
 * (7=erase, 8=program; then |rc| short blinks — see ns_trap.c / sg_status_t). */
extern void ns_trap_code(int marker, int value) __attribute__((noreturn));

void __wrap_flash_range_erase(uint32_t flash_offs, size_t count) {
    int rc = sg_flash_erase(flash_offs, (uint32_t)count);
    if (rc != SG_OK) ns_trap_code(7, rc);
}

void __wrap_flash_range_program(uint32_t flash_offs, const uint8_t *data, size_t count) {
    int rc = sg_flash_program(flash_offs, data, (uint32_t)count);
    if (rc != SG_OK) ns_trap_code(8, rc);
}
