/*
 * runtime_init_ns.c — SDK runtime-init overrides for the Non-secure R2P2
 * image (RP2350 TrustZone split). SKETCH.
 *
 * The stock SDK runtime init assumes it owns the whole chip. Under the
 * S/NS split the monitor has already done the chip-wide work (clocks,
 * PLLs, ticks, resets) before NS entry, and several stages would fault or
 * hang if run Non-secure. This file provides strong overrides for the
 * __weak SDK stages that must change; two stages that cannot run at all
 * are compiled out via PICO_RUNTIME_SKIP_INIT_* definitions in
 * ns_build.cmake:
 *
 *   PICO_RUNTIME_SKIP_INIT_BOOTROM_RESET=1
 *   PICO_RUNTIME_SKIP_INIT_PER_CORE_BOOTROM_RESET=1
 *     bootrom_state_reset() is an Arm-S-only ROM API (datasheet §5.4.8):
 *     the NS ROM table has no entry for it, so the lookup in the stock
 *     stage would fail at boot. It is also the call that disables ARM-NS
 *     bootrom API access — running it would undo the monitor's
 *     rom_set_ns_api_permission() grants even if it existed. The monitor
 *     performs the global state reset before configuring the partition.
 *
 * Stages that need NO change in NS:
 *   - runtime_init_usb_power_down: USBCTRL is NS-granted.
 *   - runtime_init_per_core_enable_coprocessors: writes CPACR, which is
 *     banked — from NS it hits CPACR_NS. Works because the monitor's
 *     NSACR grants CP0/CP4/CP10/CP11; without the grant the writes are
 *     silently ineffective and the first double operation traps.
 *   - runtime_init_spin_locks_reset: RP2350 defaults to software spin
 *     locks (erratum workaround), and the NS SIO has its own hardware
 *     spinlock bank anyway.
 *   - runtime_init_install_ram_vector_table: SCB->VTOR is banked; from NS
 *     it sets VTOR_NS.
 *   - stack guard (MPU): banked, NS MPU.
 */

#include "pico.h"
#include "hardware/clocks.h"

#include "../include/r2p2_tz_config.h"

#if !PICO_RP2350
#error runtime_init_ns.c is specific to the RP2350 TrustZone build
#endif

/* Both reset stages are NO-OPS in NS. The RESETS block is Secure-only
 * (ACCESSCTRL_RESETS resets to 0xfc — NSP/NSU clear) and MUST stay that way:
 * it can reset OTP/TRNG/SHA256/XIP, so NS holding it would breach the
 * partition. Any NS write to resets_hw bus-faults. The monitor's own
 * runtime_init already brought every peripheral out of reset before the
 * handoff, and NS inherits them at reset-default config, so NS has nothing
 * to do here. (Confirmed on target 2026-07-02: the stock reset-cycle here
 * faulted in runtime_init — LED breadcrumb stopped at "3 blinks, solid".) */
void runtime_init_early_resets(void) {
}

void runtime_init_post_clock_resets(void) {
}

/* CLOCKS is Secure-only — NS cannot configure or even read it. The monitor
 * guarantees the contract frequencies; report them into hardware_clocks'
 * table so clock_get_hz() (UART baud, I2C/SPI/ADC timing, TinyUSB) works.
 * Ticks are NOT started here: TICKS is Secure-only and the monitor has
 * already started all generators. */
void runtime_init_clocks(void) {
    clock_set_reported_hz(clk_ref,  TZ_CLK_REF_HZ);
    clock_set_reported_hz(clk_sys,  TZ_CLK_SYS_HZ);
    clock_set_reported_hz(clk_peri, TZ_CLK_PERI_HZ);
    clock_set_reported_hz(clk_usb,  TZ_CLK_USB_HZ);
    clock_set_reported_hz(clk_adc,  TZ_CLK_ADC_HZ);
    clock_set_reported_hz(clk_hstx, TZ_CLK_HSTX_HZ);
}
