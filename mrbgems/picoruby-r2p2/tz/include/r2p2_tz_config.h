/*
 * r2p2_tz_config.h — the Secure/Non-secure contract, compiled into BOTH
 * images. Single source of truth for the memory map (must match the two
 * linker scripts) and for everything the monitor promises to have set up
 * before it enters the NS image.
 */

#ifndef R2P2_TZ_CONFIG_H
#define R2P2_TZ_CONFIG_H

/* ---- flash/RAM map (see tz/README.md) ----------------------------------- */

#define TZ_SG_NSC_BASE    0x1000f000u  /* .gnu.sgstubs in memmap_monitor_s.ld */
#define TZ_SG_NSC_LAST    0x1000ffffu
#define TZ_NS_FLASH_BASE  0x10010000u  /* NS image + filesystem, to end of 4 MiB flash */
#define TZ_NS_FLASH_LAST  0x103fffffu
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
