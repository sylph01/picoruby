/*
 * tz_diag.h — monitor diagnostic record, read over SWD (Debug Probe).
 *
 * Lives at the very start of Secure RAM: **0x20080000** (own linker
 * section, placed first in RAM_S). With the probe attached:
 *
 *   (gdb) x/12wx 0x20080000        or  openocd> mdw 0x20080000 12
 *
 * or `source tz/tools/tz_diag.gdb` and run `tzdiag`. The record replaces
 * the bring-up LED blink-out as the primary diagnostic channel (the LED
 * path still exists behind R2P2_TZ_LED_DIAG for the non-W Pico 2).
 *
 * boot_stage advances through TZ_STAGE_* as main() progresses, so a hang
 * localizes to the stage that never got stamped. fault_kind != 0 means a
 * Secure-side fault handler ran (or a fatal boot check failed) and the
 * rest of the record holds the details.
 */

#ifndef TZ_DIAG_H
#define TZ_DIAG_H

#include <stdint.h>

#define TZ_DIAG_ADDR  0x20080000u
#define TZ_DIAG_MAGIC 0x545a4447u  /* "TZDG" (LE: reads 47 44 5a 54) */

/* boot_stage — mirrors the LED breadcrumb counts (A..F in phase-1 notes) */
#define TZ_STAGE_ENTERED      1u   /* monitor main() reached           */
#define TZ_STAGE_NS_VERIFIED  2u   /* .ns_manifest hash check passed   */
#define TZ_STAGE_KEYS_DERIVED 3u   /* ks_init done, SW_LOCK ratcheted  */
#define TZ_STAGE_PARTITIONED  4u   /* SAU/ACCESSCTRL/ITNS configured   */
#define TZ_STAGE_NS_LAUNCHED  5u   /* about to blxns (last stamp)      */

/* fault_kind — 0 = none; 1..63 = IPSR exception number of the Secure
 * fault handler that ran (3=HardFault 4=MemManage 5=BusFault 6=UsageFault
 * 7=SecureFault); >=0x100 = fatal boot check, no exception frame: */
#define TZ_KIND_NS_HASH_MISMATCH 0x100u
#define TZ_KIND_KEYSTORE_FAILED  0x101u

typedef struct {
    uint32_t magic;       /* TZ_DIAG_MAGIC once the monitor initialized it */
    uint32_t boot_stage;  /* TZ_STAGE_* last reached */
    uint32_t fault_kind;  /* see above */
    uint32_t pc;          /* stacked NS frame: faulting instruction */
    uint32_t lr;          /*   (0xbadadd50 = frame pointer looked bogus) */
    uint32_t xpsr;
    uint32_t msp_ns;      /* NS main stack pointer at fault time */
    uint32_t cfsr;        /* Configurable Fault Status (0xE000ED28) */
    uint32_t hfsr;        /* HardFault Status (0xE000ED2C) */
    uint32_t bfar;        /* BusFault address (0xE000ED38) */
    uint32_t sfsr;        /* SecureFault Status (0xE000EDE4) */
    uint32_t sfar;        /* SecureFault address (0xE000EDE8) */
} tz_diag_t;

#endif /* TZ_DIAG_H */
