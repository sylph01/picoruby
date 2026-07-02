/*
 * flash_ns.c — link-level replacement for hardware_flash's
 * flash_range_erase/flash_range_program in the Non-secure R2P2 image.
 * SKETCH. Same --wrap mechanism as rand_ns.c (hardware_flash is an SDK
 * INTERFACE library, so flash.c is a peer object and a plain redefinition
 * would collide): ns_build.cmake passes -Wl,--wrap=flash_range_erase and
 * --wrap=flash_range_program, redirecting callers (the littlefs/FAT HALs)
 * to the __wrap_* functions here.
 *
 * Why: the stock implementations drive the QSPI/QMI directly via
 * Arm-S-only ROM helpers (connect_internal_flash, flash_exit_xip) and
 * Secure-only XIP hardware — the first call from NS faults. The bootrom's
 * flash_op ('F','O') is the sanctioned NS path (datasheet §5.4.8.9,
 * Arm-NS supported): the monitor enables it via
 * rom_set_ns_api_permission(BOOTROM_NS_API_checked_flash_op), the ROM
 * performs the XIP exit/restore internally at Secure level, and the
 * operation is validated against the resident partition table — NS
 * callers are always checked against the NS permissions, so only the
 * filesystem partition (NS_W) is writable no matter what this code asks
 * for. A write outside it returns BOOTROM_ERROR_NOT_PERMITTED.
 *
 * Cache coherency: the ROM op does NOT flush the XIP cache, and NS cannot
 * (see sg_flash_flush_cache in r2p2_sg_api.h) — so each operation ends
 * with the flush veneer, mirroring the stock flash_range_* behavior of
 * flushing before returning.
 *
 * Callers (littlefs flash_hal.c, filesystem-fat flash_disk.c) pass flash
 * OFFSETS and already wrap calls in save_and_disable_interrupts(); the
 * SDK's rom_flash_op() additionally serializes via the bootrom FLASH_OP
 * lock and flash_safe_execute() (requires pico_flash — linked in
 * ns_build.cmake; with PICO_FLASH_ASSUME_CORE1_SAFE=1 it reduces to an
 * IRQ guard).
 *
 * Alignment contract is unchanged from stock: erase 4 KiB-aligned/-sized,
 * program 256 B-aligned/-sized — both HALs already comply.
 */

#include "pico.h"
#include "pico/bootrom.h"
#include "boot/bootrom_constants.h"
#include "hardware/regs/addressmap.h"

#include "../include/r2p2_sg_api.h"

/* Do NOT use the SDK's rom_flash_op() wrapper here: it calls
 * bootrom_try_acquire_lock(), which reads/writes a lock word in BOOTRAM
 * (0x400e0000). BOOTRAM is Secure-only, and that access runs in NS state,
 * so it bus-faults (confirmed on target 2026-07-02: BusFault, BFAR =
 * 0x400e0000). Instead call the bootrom flash_op ROM function directly:
 * from NS, rom_func_lookup returns the Non-secure 'FO' entry, which is a
 * secure gateway — the Secure bootrom does the BOOTRAM/QMI work on the
 * Secure side. It also enforces the partition table's NS permissions
 * (only the fs partition is NS-writable). Requires the monitor to have
 * enabled the checked_flash_op NS API (it does).
 *
 * The SECLEVEL field is mandatory: 0 is not a valid value, so leaving it
 * unset makes the bootrom reject the flags with BOOTROM_ERROR_INVALID_ARG
 * (confirmed on target 2026-07-02: rc=-5). From NS it must be NONSECURE. */
#define TZ_CFLASH(op) ((cflash_flags_t){ .flags = \
        ((op) << CFLASH_OP_LSB) | \
        (CFLASH_SECLEVEL_VALUE_NONSECURE << CFLASH_SECLEVEL_LSB) | \
        (CFLASH_ASPACE_VALUE_STORAGE << CFLASH_ASPACE_LSB) })

static int ns_flash_op(cflash_flags_t flags, uint32_t flash_offs,
                       uint32_t count, uint8_t *buf) {
    rom_flash_op_fn fn = (rom_flash_op_fn) rom_func_lookup(ROM_FUNC_FLASH_OP);
    return fn(flags, XIP_BASE + flash_offs, count, buf);
}

/* TEMP bring-up: on error blink the bootrom rc instead of asserting, so we
 * can read WHY checked_flash_op rejected the op (7=erase, 8=program;
 * then |rc| short blinks -> e.g. 4=NOT_PERMITTED, 10=INVALID_ADDRESS). */
extern void ns_trap_code(int marker, int value) __attribute__((noreturn));

void __wrap_flash_range_erase(uint32_t flash_offs, size_t count) {
    int rc = ns_flash_op(TZ_CFLASH(CFLASH_OP_VALUE_ERASE),
                         flash_offs, (uint32_t)count, NULL);
    if (rc != BOOTROM_OK) ns_trap_code(7, rc);
    sg_flash_flush_cache();
}

void __wrap_flash_range_program(uint32_t flash_offs, const uint8_t *data, size_t count) {
    int rc = ns_flash_op(TZ_CFLASH(CFLASH_OP_VALUE_PROGRAM),
                         flash_offs, (uint32_t)count, (uint8_t *)(uintptr_t)data);
    if (rc != BOOTROM_OK) ns_trap_code(8, rc);
    sg_flash_flush_cache();
}
