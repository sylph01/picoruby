/*
 * gpio_irq_ns.c — bank-0 GPIO interrupt vectoring for the Non-secure
 * image (RP2350 TrustZone split). SKETCH.
 *
 * RP2350 splits IO_BANK0's interrupt output per security domain
 * (datasheet §10.6.1): an event on a pin that is Non-secure in
 * GPIO_NSMASK asserts IO_IRQ_BANK0_NS (IRQ 22), never IO_IRQ_BANK0
 * (IRQ 21). Every bank-0 pin is NSMASK'd in this design, so from NS the
 * _NS line is the only one that ever fires — but the SDK is TZ-unaware
 * and wires everything to IRQ 21: hardware_gpio's shared/raw handler
 * chains, pico_cyw43_driver's host-wake handler, and their
 * irq_set_enabled calls. Net effect without this file: INTE gets set,
 * the event pends invisibly on the Secure-targeted line 22, and nothing
 * runs. First casualty was cyw43 idle RX delivery — the host-wake
 * LEVEL_HIGH IRQ is what marks the poll worker pending once the bus
 * sleep countdown expires, so WiFi TX worked while RX stalled until the
 * next synchronous ioctl drained it (WIFI-UNDER-TZ-HANDOFF.md, open
 * bug 1).
 *
 * Fix, in two halves:
 *   - the monitor ITNS-routes IRQ 22 to NS (tz_ns_irqs[] in
 *     monitor/main.c);
 *   - this file vectors IRQ 22 to whatever handler the SDK installed
 *     for IRQ 21, looked up per-fire so handler add/remove on 21 keeps
 *     working, and keeps NVIC 22 enabled from boot. Per-event gating
 *     stays where the SDK does it: the shared INTE registers (NS
 *     accesses to which are per-pin filtered but do land — unlike PADS,
 *     IO_BANK0 is not affected by erratum RP2350-E3).
 */

#include "pico.h"
#include "hardware/irq.h"
#include "hardware/regs/intctrl.h"

#if !PICO_RP2350
#error gpio_irq_ns.c is specific to the RP2350 TrustZone build
#endif

/* Strong override of crt0's weak isr_irq22 — sits in the flash vector
 * table from reset and is carried into the RAM copy, so no runtime
 * registration is needed (and irq_set_exclusive_handler on 22 would
 * only fight it). */
void isr_irq22(void) {
    irq_handler_t handler = irq_get_vtable_handler(IO_IRQ_BANK0);
    if (handler) {
        handler();
    }
}

/* NVIC enable for line 22. Constructors run pre-main via the SDK
 * runtime (audited: NS-safe — a banked NVIC_NS write). Unconditional
 * enable is fine: the line only asserts when an INTE bit is set, and
 * the SDK sets those only after installing a handler on 21. */
__attribute__((constructor))
static void gpio_irq_ns_init(void) {
    irq_set_enabled(IO_IRQ_BANK0_NS, true);
}
