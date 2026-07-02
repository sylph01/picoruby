/*
 * r2p2_tz_config.h — the Secure/Non-secure contract, compiled into BOTH
 * images. Single source of truth for the memory map (must match the two
 * linker scripts) and for everything the monitor promises to have set up
 * before it enters the NS image.
 */

#ifndef R2P2_TZ_CONFIG_H
#define R2P2_TZ_CONFIG_H

#include <stdint.h>

/* ---- NS image manifest ---------------------------------------------------
 * Monitor+NS ship-together model: the monitor authenticates the NS image
 * by SHA-256 digest. The monitor is built with a placeholder (magic = 0);
 * the packaging step (rake r2p2:tz:package) hashes the built NS binary,
 * patches this struct into the monitor's .ns_manifest section via
 * objcopy --update-section, and THEN the monitor is sealed/signed — so the
 * boot signature transitively covers the digest, and the digest covers the
 * NS bytes. Every NS change ⇒ re-patch + re-sign the monitor (accepted:
 * both images ship together).
 *
 * The byte layout below is mirrored by the packing code in
 * tasks/picoruby/r2p2.rake (little-endian u32 ×3 + 32 digest bytes = 44
 * bytes) — keep them in sync.
 *
 * `version` is carried from day one so a later field-update model (signed
 * manifest verified against a stable public key) extends this format
 * instead of replacing it. */

#define TZ_NS_MANIFEST_MAGIC 0x52324e53u  /* "R2NS" */

typedef struct {
    uint32_t magic;        /* TZ_NS_MANIFEST_MAGIC once patched; 0 = dev build */
    uint32_t version;      /* monotonic NS image version (rollback, phase 2) */
    uint32_t ns_size;      /* bytes of NS image hashed from TZ_NS_FLASH_BASE */
    uint8_t  ns_digest[32];/* SHA-256 over those bytes */
} tz_ns_manifest_t;

/* ---- flash/RAM map (see tz/README.md) ----------------------------------- */

#define TZ_SG_NSC_BASE    0x1000f000u  /* .gnu.sgstubs in memmap_monitor_s.ld */
#define TZ_SG_NSC_LAST    0x1000ffffu
#define TZ_NS_FLASH_BASE  0x10010000u  /* NS image + filesystem, to end of 4 MiB flash */
#define TZ_NS_FLASH_LAST  0x103fffffu

/* Filesystem partition as 0-based flash offsets (from r2p2_tz_pt.json:
 * fs start 3328K, size 768K, nonsecure "rw"). The Secure flash veneers
 * clamp NS erase/program to this window so NS cannot touch the monitor
 * (0..60K), the NSC veneers, or the NS code/manifest region. */
#define TZ_FS_OFFSET  0x00340000u  /* 3328 KiB */
#define TZ_FS_SIZE    0x000c0000u  /* 768 KiB  */
#define TZ_NS_RAM_BASE    0x20000000u  /* all 512 KiB striped SRAM */
#define TZ_NS_RAM_LAST    0x2007ffffu

/* ---- clock contract ------------------------------------------------------
 * CLOCKS/PLLs/XOSC are Secure-only; the monitor runs the stock SDK clock
 * init (runtime_init_clocks + tick start) before NS entry and guarantees
 * these frequencies. The NS image cannot even read the CLOCKS registers —
 * its runtime_init_clocks override (tz/ns/runtime_init_ns.c) just reports
 * these values into hardware_clocks' frequency table so clock_get_hz()
 * (UART baud, I2C/SPI timing, ...) computes correctly.
 *
 * If the monitor ever changes its clock setup, these move in lockstep —
 * that is the point of putting them in the contract header. */

#define TZ_CLK_REF_HZ   12000000u   /* XOSC */
#define TZ_CLK_SYS_HZ  150000000u   /* SDK default SYS_CLK_HZ on RP2350 */
#define TZ_CLK_PERI_HZ TZ_CLK_SYS_HZ
#define TZ_CLK_USB_HZ   48000000u
#define TZ_CLK_ADC_HZ   48000000u
#define TZ_CLK_HSTX_HZ TZ_CLK_SYS_HZ

/* ---- other monitor guarantees at NS entry --------------------------------
 *  - All NS-granted peripherals (tz/README.md ACCESSCTRL table) are out of
 *    reset with their clocks running; TICKS generators are started
 *    (timers and watchdog tick).
 *  - DMA channels 0..TZ_NS_DMA_CHANNELS-1 are NS; the rest are Secure.
 *  - NSACR grants CP0 (GPIO coprocessor), CP4 (DCP), CP10/CP11 (FPU).
 *  - Bootrom NS APIs enabled: checked_flash_op,
 *    flash_runtime_to_storage_addr, get_sys_info, reboot. Everything else
 *    (notably otp_access, secure_call) is disabled.
 *  - bootrom_state_reset is Arm-S-only and must never be called from NS. */

#define TZ_NS_DMA_CHANNELS 12u

#endif /* R2P2_TZ_CONFIG_H */
