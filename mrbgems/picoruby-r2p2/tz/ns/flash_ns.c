/*
 * flash_ns.c — link-level replacement for hardware_flash's
 * flash_range_erase/flash_range_program in the Non-secure R2P2 image.
 * SKETCH. Same mechanism as rand_ns.c: this file is a direct source of
 * the firmware target, so the linker never pulls flash.o from the
 * hardware_flash archive.
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
#include "hardware/flash.h"
#include "hardware/regs/addressmap.h"

#include "../include/r2p2_sg_api.h"

/* No QMI address translation is configured in R2P2, and the partition
 * table is expressed in storage addresses: use the storage address space
 * (ASPACE_STORAGE), addressed as XIP_BASE + offset per §5.4.8.9. */
#define TZ_CFLASH(op) ((cflash_flags_t){ .flags = \
        ((op) << CFLASH_OP_LSB) | \
        (CFLASH_SECLEVEL_VALUE_NONSECURE << CFLASH_SECLEVEL_LSB) | \
        (CFLASH_ASPACE_VALUE_STORAGE << CFLASH_ASPACE_LSB) })

void flash_range_erase(uint32_t flash_offs, size_t count) {
    int rc = rom_flash_op(TZ_CFLASH(CFLASH_OP_VALUE_ERASE),
                          XIP_BASE + flash_offs, (uint32_t)count, NULL);
    hard_assert(rc == BOOTROM_OK);
    sg_flash_flush_cache();
}

void flash_range_program(uint32_t flash_offs, const uint8_t *data, size_t count) {
    /* rom_flash_op takes a non-const buf; program ops never write to it. */
    int rc = rom_flash_op(TZ_CFLASH(CFLASH_OP_VALUE_PROGRAM),
                          XIP_BASE + flash_offs, (uint32_t)count,
                          (uint8_t *)(uintptr_t)data);
    hard_assert(rc == BOOTROM_OK);
    sg_flash_flush_cache();
}
