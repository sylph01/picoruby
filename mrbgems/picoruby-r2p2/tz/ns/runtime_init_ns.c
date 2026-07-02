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
#include "hardware/resets.h"
#include "hardware/clocks.h"

#include "../include/r2p2_tz_config.h"

#if !PICO_RP2350
#error runtime_init_ns.c is specific to the RP2350 TrustZone build
#endif

/* RESETS bits the NS image is allowed to touch — exactly the ACCESSCTRL
 * NS-granted peripherals (RESETS access rides on the per-peripheral bits,
 * §10.6.2). Touching Secure-only bits from NS is at best ignored; waiting
 * on their RESET_DONE would hang forever, which is why the stock
 * mask-everything stages must not run. */
#define TZ_NS_RESETS_MASK ( \
        (1u << RESET_ADC)        | \
        (1u << RESET_DMA)        | \
        (1u << RESET_HSTX)       | \
        (1u << RESET_I2C0)       | \
        (1u << RESET_I2C1)       | \
        (1u << RESET_IO_BANK0)   | \
        (1u << RESET_PADS_BANK0) | \
        (1u << RESET_PIO0)       | \
        (1u << RESET_PIO1)       | \
        (1u << RESET_PIO2)       | \
        (1u << RESET_PWM)        | \
        (1u << RESET_SPI0)       | \
        (1u << RESET_SPI1)       | \
        (1u << RESET_SYSINFO)    | \
        (1u << RESET_TBMAN)      | \
        (1u << RESET_TIMER0)     | \
        (1u << RESET_UART0)      | \
        (1u << RESET_UART1)      | \
        (1u << RESET_USBCTRL))

/* Stock stage resets ~everything then unresets clk_sys/clk_ref-only
 * peripherals. In NS: reset-cycle only our own peripherals for a clean
 * start (the monitor left them unreset after its full init); all their
 * clocks are already running, so unreset everything in one go.
 *
 * TODO(verify on target): confirm NS reads of RESET_DONE reflect
 * NS-granted bits (RAZ semantics for the rest) rather than bus-faulting. */
void runtime_init_early_resets(void) {
    reset_block_mask(TZ_NS_RESETS_MASK);
    unreset_block_mask_wait_blocking(TZ_NS_RESETS_MASK);
}

/* Stock stage is a no-op wait: by NS entry every NS peripheral is already
 * out of reset (see above), and Secure-only bits must not be waited on. */
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
