/*
 * R2P2 Secure monitor — boot, partition setup, Non-secure handoff. SKETCH.
 *
 * Boot flow this file assumes (decided against pico-sdk 2.2.0 and RP2350
 * datasheet §5/§10; bootrom facts noted inline):
 *
 *  1. The monitor and the NS R2P2 image are packaged and signed as ONE unit:
 *     the monitor's IMAGE_DEF signature covers 0x10000000..NS image end, so
 *     the bootrom's RCP-hardened ECDSA verifies both at boot. (The bootrom
 *     cannot launch an EXE_SECURITY=NS image itself — the rp2350_arm_ns
 *     family is "not directly bootable" — so chain_image() is not used;
 *     the monitor performs the NS entry.)
 *  2. The bootrom enters the monitor in the Secure state with the SAU
 *     already ENABLED (ALLNS=0) and SAU region 7 programmed over the whole
 *     bootrom. Region 7 is the bootrom's — never touch it. Regions 0-6 are
 *     ours; we use 0-2.
 *  3. The monitor executes XIP from Secure flash (phase-1 decision: the
 *     threat model is a compromised NS runtime, not physical flash swap;
 *     revisit with encrypted boot for the latter).
 *
 * IDAU facts this configuration relies on (datasheet §10.2.2):
 *  - XIP (0x1xxxxxxx) and SRAM are IDAU-Non-secure: attribution is
 *    max(SAU, IDAU), so anything NOT covered by an NS SAU region falls to
 *    the Secure SAU background — that alone protects monitor flash and
 *    SRAM8/9 from the NS CPU.
 *  - APB/AHB peripherals and SIO are IDAU-Exempt: never spend SAU regions
 *    on them; ACCESSCTRL assigns peripherals, SIO is banked by bus
 *    security attribute.
 *  - The CPU-side SAU does not filter other bus managers: ACCESSCTRL must
 *    also strip NS access from SRAM8/9 (they reset NS-accessible!), and
 *    every DMA channel handed to NS gets SECCFG_CHx = NSP + LOCK.
 */

#include <stdint.h>
#include <string.h>

#include "pico/bootrom.h"
#include "pico/sha256.h"
#include "boot/bootrom_constants.h"
#include "hardware/sync.h"
#include "hardware/structs/sau.h"
#include "hardware/structs/scb.h"
#include "hardware/structs/sio.h"
#include "hardware/structs/psm.h"
#include "hardware/structs/accessctrl.h"
#include "hardware/structs/nvic.h"
#include "hardware/structs/m33.h"
#include "hardware/structs/dma.h"
#include "hardware/regs/m33.h"
#include "hardware/regs/accessctrl.h"
#include "hardware/regs/dma.h"
#include "hardware/regs/intctrl.h"
#include "hardware/gpio.h"
#include "hardware/powman.h"

#include "../include/r2p2_sg_api.h"
#include "../include/r2p2_tz_config.h"  /* memory map, clock contract, TZ_NS_DMA_CHANNELS */
#include "tz_core1.h"
#include "keystore.h"
#include "tz_diag.h"

/* ---- diagnostics ----------------------------------------------------------
 * Primary channel: the tz_diag record at 0x20080000 (tz_diag.h), stamped
 * at every boot stage and filled by the fault handlers — read it over SWD
 * (Debug Probe; see tz/tools/PROBE.md). Halting is a quiet wfi loop so an
 * attached probe finds an idle, inspectable core.
 *
 * Secondary channel (R2P2_TZ_LED_DIAG=1, non-W Pico 2 only): the phase-1
 * LED breadcrumbs — stage blink counts, strobe on NS-hash mismatch, and
 * the faulting-PC nibble read-out. Compiled out for probe boards and for
 * production. */

static volatile tz_diag_t tz_diag __attribute__((section(".tz_diag"), used));

static void __attribute__((noreturn)) diag_halt(void);

static void diag_stage(uint32_t stage);

/* Fill the fault record from the banked NS state + fault status registers.
 * NS runs thread mode on MSP_NS, so the 8-word exception frame is there;
 * guard the SP so a bogus value can't nest-fault. */
static void __attribute__((noreturn)) diag_fault(void) {
    uint32_t msp_ns, ipsr;
    __asm volatile ("mrs %0, msp_ns" : "=r" (msp_ns));
    __asm volatile ("mrs %0, ipsr" : "=r" (ipsr));
    tz_diag.fault_kind = ipsr & 0x1ffu;
    tz_diag.msp_ns = msp_ns;
    if (msp_ns >= 0x20000000u && msp_ns < (0x20080000u - 32u)) {
        const uint32_t *frame = (const uint32_t *)msp_ns;
        tz_diag.lr   = frame[5];
        tz_diag.pc   = frame[6];
        tz_diag.xpsr = frame[7];
    } else {
        tz_diag.pc = 0xbadadd50u;
    }
    tz_diag.cfsr = *(volatile uint32_t *)0xe000ed28u;
    tz_diag.hfsr = *(volatile uint32_t *)0xe000ed2cu;
    tz_diag.bfar = *(volatile uint32_t *)0xe000ed38u;
    tz_diag.sfsr = *(volatile uint32_t *)0xe000ede4u;
    tz_diag.sfar = *(volatile uint32_t *)0xe000ede8u;
    diag_halt();
}

#if R2P2_TZ_LED_DIAG

#define TZ_LED_PIN 25
static void busy_delay(uint32_t loops) {
    for (volatile uint32_t i = 0; i < loops; i++) __asm volatile ("nop");
}
/* ~1 ms of busy-wait at 150 MHz (rough; the volatile loop is a handful of
 * cycles). Timings below are deliberately slow so blinks are countable. */
#define BUSY_MS(n) ((n) * 25000u)
#define LED_ON_MS  BUSY_MS(120)   /* breadcrumb blink on/off */
#define LED_GAP_MS BUSY_MS(550)   /* gap between breadcrumb blink groups */
static void led_init(void) { gpio_init(TZ_LED_PIN); gpio_set_dir(TZ_LED_PIN, GPIO_OUT); }
static void led_set(bool on) { gpio_put(TZ_LED_PIN, on); }
static void led_blink(uint n) {
    for (uint k = 0; k < n; k++) {
        led_set(true);  busy_delay(LED_ON_MS);
        led_set(false); busy_delay(LED_ON_MS);
    }
    busy_delay(LED_GAP_MS);
}

/* Blink one hex nibble MSB-first: value 1..15 = that many short blinks,
 * value 0 = one long pulse (so 0 is distinguishable from "no blinks"). */
static void led_nibble(uint v) {
    if (v == 0) {
        led_set(true); busy_delay(BUSY_MS(1400)); led_set(false);  /* long = 0 */
    } else {
        for (uint i = 0; i < v; i++) {
            led_set(true);  busy_delay(BUSY_MS(350));
            led_set(false); busy_delay(BUSY_MS(350));
        }
    }
    busy_delay(BUSY_MS(2200)); /* inter-nibble gap */
}

/* LED halt: blink the recorded faulting PC (or the stage that failed) as 8
 * nibbles MSB-first, forever — the phase-1 read-out, map via addr2line. */
static void __attribute__((noreturn)) diag_halt(void) {
    uint32_t w = tz_diag.fault_kind >= 0x100u ? tz_diag.fault_kind
                                              : tz_diag.pc;
    for (;;) {
        for (int s = 28; s >= 0; s -= 4) led_nibble((w >> s) & 0xfu);
        busy_delay(BUSY_MS(5000)); /* long gap before repeating */
    }
}

static void diag_stage(uint32_t stage) {
    tz_diag.boot_stage = stage;
    led_blink(stage);
}

#else /* !R2P2_TZ_LED_DIAG — probe boards (Pico 2 W) and production */

static void led_init(void) {}
static void led_set(bool on) { (void)on; }

static void __attribute__((noreturn)) diag_halt(void) {
    for (;;) __asm volatile ("wfi");  /* quiet; attach the probe and read
                                       * tz_diag at 0x20080000 */
}

static void diag_stage(uint32_t stage) {
    tz_diag.boot_stage = stage;
}

#endif /* R2P2_TZ_LED_DIAG */

/* NS-origin bus/usage/mem/secure faults escalate here (BFHFNMINS=0, NS
 * handlers off). A HardFault is usually an escalated NS UsageFault
 * (undefined instr / NOCP coprocessor / unaligned). Each handler fills the
 * tz_diag record (kind = its IPSR exception number, plus the stacked NS
 * PC/LR and the fault status registers) and halts — read over SWD, or as
 * the LED PC read-out when R2P2_TZ_LED_DIAG=1. */
void isr_busfault(void)    { diag_fault(); }
void isr_hardfault(void)   { diag_fault(); }
void isr_securefault(void) { diag_fault(); }
void isr_usagefault(void)  { diag_fault(); }
void isr_memmanage(void)   { diag_fault(); }

/* All ACCESSCTRL registers except GPIO_NSMASK* require this password in the
 * upper half of the write data; writes without it bus-fault (§10.6). */
#define AC_PASSWORD 0xacce0000u

/* Manager bits (DBG/DMA/CORE1/CORE0) + all four security levels. Peripheral
 * registers reset with NSP/NSU clear, memory devices reset to 0xff. */
#define AC_ALLOW_ALL     (AC_PASSWORD | 0xffu)
#define AC_SECURE_ONLY   (AC_PASSWORD | (0xffu & ~(ACCESSCTRL_UART0_NSP_BITS | ACCESSCTRL_UART0_NSU_BITS)))

/* IRQs retargeted to the NS vector table via NVIC ITNS. Everything an NS
 * peripheral can raise; SecureFault/faults stay Secure (AIRCR.BFHFNMINS=0,
 * the reset default, is deliberately left alone). */
static const uint8_t tz_ns_irqs[] = {
    TIMER0_IRQ_0, TIMER0_IRQ_1, TIMER0_IRQ_2, TIMER0_IRQ_3,
    PWM_IRQ_WRAP_0, PWM_IRQ_WRAP_1,
    DMA_IRQ_0, DMA_IRQ_1, DMA_IRQ_2, DMA_IRQ_3,
    USBCTRL_IRQ,
    PIO0_IRQ_0, PIO0_IRQ_1, PIO1_IRQ_0, PIO1_IRQ_1, PIO2_IRQ_0, PIO2_IRQ_1,
    /* Bank-0 GPIO interrupts are split per security domain (§10.6.1): an
     * event on an NSMASK'd pin asserts IO_IRQ_BANK0_NS, never IO_IRQ_BANK0.
     * All 30 user pins are NSMASK'd here, so _NS is the line that actually
     * fires; 21 is kept routed too so the SDK's TZ-unaware
     * irq_set_enabled(IO_IRQ_BANK0) stays a working no-op. NS-side vectoring
     * of the _NS line is ns/gpio_irq_ns.c. Found the hard way: the cyw43
     * host-wake LEVEL_HIGH IRQ never delivered → idle RX stalled. */
    IO_IRQ_BANK0, IO_IRQ_BANK0_NS,
    SPI0_IRQ, SPI1_IRQ,
    UART0_IRQ, UART1_IRQ,
    ADC_IRQ_FIFO,
    I2C0_IRQ, I2C1_IRQ,
};

/* ---- NS image verification ----------------------------------------------
 * Ship-together model: the packaging step patches the built NS image's
 * SHA-256 into .ns_manifest and the monitor is signed afterwards, so the
 * boot signature covers this struct. A dev build (unpackaged, magic still
 * 0) skips the check so the plain cmake build remains bootable. */

static const tz_ns_manifest_t tz_ns_manifest
    __attribute__((section(".ns_manifest"), used)) = { .magic = 0 };

static void __attribute__((noreturn)) verify_failed(void) {
    /* NS hash mismatch. Recorded as TZ_KIND_NS_HASH_MISMATCH for the probe;
     * with the LED enabled, a rapid strobe = self-identifying (distinct
     * from any blink-count breadcrumb). Recovery is BOOTSEL, upstream in
     * the bootrom. */
    tz_diag.fault_kind = TZ_KIND_NS_HASH_MISMATCH;
#if R2P2_TZ_LED_DIAG
    for (;;) {
        led_set(true);  busy_delay(1000000u);   /* ~40 ms */
        led_set(false); busy_delay(1000000u);
    }
#else
    diag_halt();
#endif
}

static void verify_ns_image(void) {
    if (tz_ns_manifest.magic != TZ_NS_MANIFEST_MAGIC) {
        return; /* dev build: no digest was packaged in */
    }
    if (tz_ns_manifest.ns_size == 0 ||
        tz_ns_manifest.ns_size > (TZ_NS_FLASH_LAST + 1u - TZ_NS_FLASH_BASE)) {
        verify_failed();
    }
    pico_sha256_state_t state;
    if (pico_sha256_try_start(&state, SHA256_BIG_ENDIAN, false) != PICO_OK) {
        verify_failed(); /* nothing else owns the engine this early */
    }
    pico_sha256_update_blocking(&state, (const uint8_t *)TZ_NS_FLASH_BASE,
                                tz_ns_manifest.ns_size);
    sha256_result_t result;
    pico_sha256_finish(&state, &result);
    /* Plain memcmp is fine: both values are public (a digest, not a key). */
    if (memcmp(result.bytes, tz_ns_manifest.ns_digest, sizeof result.bytes) != 0) {
        verify_failed();
    }
}

/* ---- key material ------------------------------------------------------- */

/* Keystore lives in keystore.c (slot -> OTP mapping, policies, handles,
 * rollback counter). ks_init() reads/derives the slot keys — chip-ID dev
 * fallback on blank OTP pages — and ratchets SW_LOCK behind itself. */

static void monitor_derive_keys(void) {
    if (ks_init() != SG_OK) {
        /* SHA engine unavailable at boot: cannot happen, but never
         * continue with an unkeyed keystore. */
        tz_diag.fault_kind = TZ_KIND_KEYSTORE_FAILED;
        diag_halt();
    }
}

/* ---- AON wall clock ------------------------------------------------------- */

/* Start the POWMAN 1 kHz timer (the sg_aon_* wall clock, and the wake
 * source for sg_deep_sleep) on the XOSC tick source. If it is already
 * running — a watchdog reboot, POWMAN survives — leave the count alone so
 * the wall clock persists across NS-requested reboots, same as a real RTC. */
static void monitor_aon_init(void) {
    if (!powman_timer_is_running()) {
        powman_timer_set_1khz_tick_source_xosc();
        powman_timer_set_ms(0);
        powman_timer_start();
    }
}

/* ---- partition configuration -------------------------------------------- */

static void sau_region(uint32_t region, uint32_t base, uint32_t last, bool nsc) {
    sau_hw->rnr = region;
    sau_hw->rbar = base & M33_SAU_RBAR_BADDR_BITS;
    sau_hw->rlar = (last & M33_SAU_RLAR_LADDR_BITS)   /* 32-byte granules */
                 | (nsc ? M33_SAU_RLAR_NSC_BITS : 0)
                 | M33_SAU_RLAR_ENABLE_BITS;
}

/* Program the SAU's three NS regions and enable it (ALLNS=0, background
 * Secure). The SAU is banked per core, so this configures whichever core
 * runs it — core 0 in partition_configure, core 1 in its NS trampoline —
 * from one source of truth. Region 7 (bootrom) untouched. */
static void tz_sau_configure_ns_regions(void) {
    sau_region(0, TZ_SG_NSC_BASE, TZ_SG_NSC_LAST, true);   /* veneers: S+NSC */
    sau_region(1, TZ_NS_FLASH_BASE, TZ_NS_FLASH_LAST, false); /* NS code+FS  */
    sau_region(2, TZ_NS_RAM_BASE, TZ_NS_RAM_LAST, false);     /* NS RAM      */
    sau_hw->ctrl = M33_SAU_CTRL_ENABLE_BITS;
}

static void partition_configure(void) {
    /* SAU (this core = core 0). Already enabled by the bootrom, but
     * reasserting is harmless and self-documenting. */
    tz_sau_configure_ns_regions();

    /* ACCESSCTRL, memory side: strip NS from the monitor's SRAM banks.
     * They reset to 0xff (NS-accessible), and the SAU only filters the CPU —
     * without this, an NS-programmed bus master could still reach them. */
    accessctrl_hw->sram[8] = AC_SECURE_ONLY;
    accessctrl_hw->sram[9] = AC_SECURE_ONLY;

    /* ACCESSCTRL, peripheral side: grant NS to everything R2P2 drives.
     * Peripherals not listed keep their Secure-only reset value: OTP, TRNG,
     * SHA256, CLOCKS, XOSC, ROSC, PLLs, POWMAN, TICKS, XIP_QMI, XIP_CTRL,
     * XIP_AUX, BUSCTRL, SYSCFG, PADS_QSPI, TIMER1, CORESIGHT_*. */
    accessctrl_hw->dma        = AC_ALLOW_ALL;
    accessctrl_hw->usbctrl    = AC_ALLOW_ALL;
    accessctrl_hw->pio[0]     = AC_ALLOW_ALL;
    accessctrl_hw->pio[1]     = AC_ALLOW_ALL;
    accessctrl_hw->pio[2]     = AC_ALLOW_ALL;
    accessctrl_hw->io_bank[0] = AC_ALLOW_ALL;
    accessctrl_hw->pads_bank0 = AC_ALLOW_ALL;
    accessctrl_hw->adc0       = AC_ALLOW_ALL;
    accessctrl_hw->hstx       = AC_ALLOW_ALL;
    accessctrl_hw->i2c[0]     = AC_ALLOW_ALL;
    accessctrl_hw->i2c[1]     = AC_ALLOW_ALL;
    accessctrl_hw->pwm        = AC_ALLOW_ALL;
    accessctrl_hw->spi[0]     = AC_ALLOW_ALL;
    accessctrl_hw->spi[1]     = AC_ALLOW_ALL;
    accessctrl_hw->timer[0]   = AC_ALLOW_ALL;
    accessctrl_hw->uart[0]    = AC_ALLOW_ALL;
    accessctrl_hw->uart[1]    = AC_ALLOW_ALL;
    accessctrl_hw->watchdog   = AC_ALLOW_ALL;  /* NS reboot re-enters secure boot */
    accessctrl_hw->sysinfo    = AC_ALLOW_ALL;
    accessctrl_hw->tbman      = AC_ALLOW_ALL;

    /* Grant NS access to the RESETS block itself. Peripheral drivers
     * (uart_init, i2c_init, spi_init, ...) reset their block on init via
     * RESETS, which faults from NS unless the block is NS-accessible
     * (datasheet §10.6.2.2: NS reset of a peripheral needs BOTH the
     * peripheral NS-granted AND the RESETS block NS-granted). This is safe:
     * each reset bit is independently gated by that peripheral's own
     * ACCESSCTRL, so NS still cannot reset OTP/XIP/CLOCKS/etc. (they remain
     * Secure-only per-peripheral above). */
    accessctrl_hw->resets     = AC_ALLOW_ALL;

    /* GPIO: user pins to NS (both domains), QSPI pads stay Secure-only.
     * GPIO_NSMASK is the one ACCESSCTRL register with no password. Pico 2
     * (RP2350A) has GPIOs 0-29 in bank 0; USB DP/DM are NSMASK1 bits 30/31
     * per §10.6.1 and must be NS for TinyUSB. */
    accessctrl_hw->gpio_nsmask[0] = 0x3fffffffu;
    accessctrl_hw->gpio_nsmask[1] = 0xc0000000u;

    /* Pad bring-up for the NS pins. Found on hardware (pico2_w, 2026-07-07):
     * NS writes to PADS_BANK0 do not land — the SDK's gpio_init/
     * gpio_set_function pad writes (all via the atomic aliases) are
     * silently dropped, leaving every pad at its reset value: ISO latch
     * set, input disabled. Nothing NS "configures" ever reaches a pin
     * (first casualty: the CYW43 PIO-SPI — WL_REG_ON never actually
     * powered the WiFi chip; probe_up=-6 EIO). Empirically verified:
     * clearing ISO from the Secure side makes the same NS bring-up
     * succeed at once. So the monitor de-isolates and input-enables every
     * NSMASK'd bank-0 pad: reset value minus ISO plus IE (pull-down and
     * schmitt retained — the state stock firmware reaches after
     * gpio_init).
     *
     * Root cause (datasheet TODO resolved 2026-07-07): erratum RP2350-E3.
     * On the QFN-60 package (this chip), NS access to PADS_BANK0 register
     * N is gated by the WRONG GPIO_NSMASK bit — the QFN-80→60 pad
     * remapping was left out of the permission wiring — so with
     * nsmask0=0x3fffffff a scrambled subset of pads is NS-writable and
     * the rest silently ignore NS writes (per-pin filter is RAZ/WI, not a
     * bus fault; nothing to do with atomic aliases — plain NS pad writes
     * are dropped the same way). The erratum's prescribed workaround is
     * exactly this: Secure-side pad setup, plus a veneer if NS ever needs
     * runtime pull/drive changes (it will: GPIO.pull_up et al. — add an
     * sg_pad_write veneer when a gem actually needs it). Fixed in the A4
     * stepping. */
    for (uint32_t pin = 0; pin < 30; pin++) {
        if (accessctrl_hw->gpio_nsmask[0] & (1u << pin)) {
            hw_write_masked(&pads_bank0_hw->io[pin],
                            PADS_BANK0_GPIO0_IE_BITS,
                            PADS_BANK0_GPIO0_IE_BITS | PADS_BANK0_GPIO0_ISO_BITS);
        }
    }

    /* DMA: hand the first TZ_NS_DMA_CHANNELS channels to NS-Privileged and
     * LOCK the level (it would lock at first use anyway; locking now makes
     * the assignment explicit). Remaining channels stay Secure. */
    for (uint32_t ch = 0; ch < TZ_NS_DMA_CHANNELS; ch++) {
        dma_hw->seccfg_ch[ch] = DMA_SECCFG_CH0_P_BITS | DMA_SECCFG_CH0_LOCK_BITS;
    }
    /* NS DMA IRQs: route IRQ0/1 at NS level so NS can see its channels'
     * interrupt state (§12.6, SECCFG_IRQ security must not exceed channel). */
    dma_hw->seccfg_irq[0] = DMA_SECCFG_CH0_P_BITS;
    dma_hw->seccfg_irq[1] = DMA_SECCFG_CH0_P_BITS;

    /* NVIC ITNS: NS-peripheral IRQs vector straight to the NS vector table;
     * no Secure trampoline. (Equivalent to irq_assign_to_ns() which needs
     * PICO_SECURE=1; written directly to keep the sketch self-contained.) */
    for (uint32_t i = 0; i < count_of(tz_ns_irqs); i++) {
        uint32_t irq = tz_ns_irqs[i];
        nvic_hw->itns[irq / 32] |= 1u << (irq % 32);
    }

    /* Bootrom NS APIs all reset to disabled; enable exactly what NS R2P2
     * needs. checked_flash_op is the filesystem write path — validated by
     * the bootrom against the partition table (FS partition carries the
     * PICOBIN_PARTITION_PERMISSION_NS_W bit; monitor firmware regions do
     * not). otp_access and secure_call stay disabled: keys go through the
     * sg_* veneers only. */
    rom_set_ns_api_permission(BOOTROM_NS_API_checked_flash_op, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_flash_runtime_to_storage_addr, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_get_sys_info, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_reboot, true);

    /* Core 1 is deliberately NOT pinned Non-secure here (an earlier design
     * set ACCESSCTRL FORCE_CORE_NS.CORE1). FORCE_CORE_NS forces core 1's
     * bus accesses NS *unconditionally* — including while it executes its
     * own bootrom launch loop, which runs from Secure ROM and mailboxes via
     * the Secure SIO alias. Forced NS, core 1 bus-faults on that Secure
     * ROM/SIO the instant it is released, so it can never complete the
     * launch handshake (device-verified dead, 2026-07-11). Instead core 1
     * is launched Secure into a monitor trampoline that does the S->NS
     * transition itself (tz_core1_launch_ns); thereafter core 1's own
     * banked SAU + ACCESSCTRL constrain it exactly as they do core 0's NS
     * thread. See tz_core1.h / core1_ns_trampoline. */

    /* Freeze the configuration: further ACCESSCTRL writes from the cores
     * are ignored (LOCK bits are one-way until reset). DEBUG left unlocked
     * during bring-up — set ACCESSCTRL_LOCK_DEBUG_BITS for production. */
    accessctrl_hw->lock = AC_PASSWORD
                        | ACCESSCTRL_LOCK_CORE0_BITS
                        | ACCESSCTRL_LOCK_CORE1_BITS
                        | ACCESSCTRL_LOCK_DMA_BITS;
}

/* ---- Non-secure launch --------------------------------------------------- */

/* The NS image's vector table sits at the start of its .text (crt0
 * .vectors), i.e. at TZ_NS_FLASH_BASE. */
typedef void (*ns_reset_fn)(void) __attribute__((cmse_nonsecure_call));

/* Grant NS access to the coprocessors R2P2 uses, matching what the SDK's
 * runtime_init_per_core_enable_coprocessors will then enable in CPACR_NS:
 * CP10/CP11 FPU (R2P2 builds hard-float), CP4 DCP (the SDK's double-
 * precision routines — the mruby VM is double-heavy), CP0 GPIO coprocessor.
 * Without a grant the NS CPACR write is ineffective and the first use
 * traps. CP7 (RCP) deliberately stays Secure. NSACR/CPACR are banked per
 * core, so this grants for whichever core runs it. */
static void tz_grant_ns_coprocessors(void) {
    m33_hw->nsacr |= M33_NSACR_CP0_BITS | M33_NSACR_CP4_BITS
                   | M33_NSACR_CP10_BITS | M33_NSACR_CP11_BITS;
    m33_ns_hw->cpacr |= M33_CPACR_CP0_BITS | M33_CPACR_CP4_BITS
                      | M33_CPACR_CP10_BITS | M33_CPACR_CP11_BITS;
}

static void __attribute__((noreturn)) ns_launch(void) {
    const uint32_t *ns_vtor = (const uint32_t *)TZ_NS_FLASH_BASE;

    /* NS banked SCS via the PPB_NONSEC alias: vector table + main stack. */
    m33_ns_hw->vtor = (uintptr_t)ns_vtor;
    __asm volatile ("msr msp_ns, %0" :: "r" (ns_vtor[0]));

    tz_grant_ns_coprocessors();

    /* AIRCR defaults kept: BFHFNMINS=0 (bus/hard faults target Secure),
     * SYSRESETREQS=0 (NS may request system reset — the watchdog is NS
     * anyway and any reset re-enters secure boot).
     * TODO: seal the Secure stacks (store 0xfef5eda5 at the stack limits,
     * ARM stack-sealing recommendation) in crt0/startup.
     * Core 1: NS starts it with the sg_launch_core1_ns veneer, which
     * launches it Secure into core1_ns_trampoline (below) — the same
     * S->NS transition this function does for core 0. */

    diag_stage(TZ_STAGE_NS_LAUNCHED); /* (F) SCS setup survived — blxns next */
    led_set(true);

    /* cmse_nonsecure_call: the compiler clears non-argument registers and
     * emits BLXNS; the target address needs its LSB clear for the NS
     * transition, which GCC handles via the function-pointer bit-clear. */
    ns_reset_fn ns_reset = (ns_reset_fn)(uintptr_t)ns_vtor[1];
    ns_reset();
    __builtin_unreachable();
}

/* ---- core 1 (Non-secure) launch ----------------------------------------- */

/* Inter-core FIFO helpers (bootrom mailbox). ~10M spins ≈ a few hundred ms
 * at 150 MHz; the bootrom answers in microseconds, the margin covers NS
 * IRQs preempting the handshake. Bounded so a wedged core 1 is an error,
 * never a Secure hang. */
#define CORE1_FIFO_SPINS 10000000u

static bool core1_fifo_push(uint32_t val) {
    for (uint32_t spins = CORE1_FIFO_SPINS; spins; spins--) {
        if (sio_hw->fifo_st & SIO_FIFO_ST_RDY_BITS) {
            sio_hw->fifo_wr = val;
            __sev();
            return true;
        }
    }
    return false;
}

static bool core1_fifo_pop(uint32_t *out) {
    for (uint32_t spins = CORE1_FIFO_SPINS; spins; spins--) {
        if (sio_hw->fifo_st & SIO_FIFO_ST_VLD_BITS) {
            *out = sio_hw->fifo_rd;
            return true;
        }
    }
    return false;
}

static void core1_fifo_drain(void) {
    while (sio_hw->fifo_st & SIO_FIFO_ST_VLD_BITS) (void)sio_hw->fifo_rd;
}

/* NS entry params handed to the trampoline. Core-1 launch is serialized by
 * the veneer try-lock, so a single slot suffices. Secure RAM (SRAM8/9,
 * AC_SECURE_ONLY) — the trampoline reads it while still Secure; NS never
 * touches it. */
static struct {
    uintptr_t ns_vtor;
    uintptr_t ns_entry;
    uintptr_t ns_stack_top;
} core1_ns;

/* Secure stack for the trampoline (bootrom sets SP to this before jumping).
 * The trampoline's deepest path is trampoline -> tz_sau_configure_ns_regions
 * -> sau_region, ~32 B of frames; 80 B is comfortable margin. Kept small
 * because RAM_S (SRAM8/9) is only 8 KiB and nearly full. Nothing preempts
 * the ~dozen-instruction Secure trampoline (core 1 has no NVIC sources
 * enabled yet), so no exception frame lands here. */
static uint32_t core1_tramp_stack[20] __attribute__((aligned(8)));

/* Runs on core 1 in Secure state — the bootrom launched it here. Mirror
 * core 0's crossing into NS: configure core 1's banked SAU and coprocessor
 * grants, point NS VTOR/MSP at the caller's entry, then BXNS. Everything
 * before the transition is trusted monitor code executing Secure; after it
 * core 1 is genuinely Non-secure and its own SAU + ACCESSCTRL constrain it. */
static void __attribute__((noreturn)) core1_ns_trampoline(void) {
    tz_sau_configure_ns_regions();   /* core 1's banked SAU (same as core 0) */
    tz_grant_ns_coprocessors();      /* core 1's banked NSACR/CPACR          */

    m33_ns_hw->vtor = core1_ns.ns_vtor;
    __asm volatile ("msr msp_ns, %0" :: "r" (core1_ns.ns_stack_top));

    ns_reset_fn ns_entry = (ns_reset_fn)core1_ns.ns_entry;
    ns_entry();                      /* BXNS into the NS entry point */
    __builtin_unreachable();
}

/* Whether a payload is live on core 1 (deep-sleep gate). */
static bool core1_running;

/* Core 1's RCP salt: seeded once by the bootrom at cold boot (varm_boot_path
 * step 4, core 0 writes both cores' salts) and NOT cleared by a PSM
 * FRCE_OFF PROC1 pulse — the SDK's multicore_reset_core1/relaunch relies on
 * exactly that. So after our reset pulse core 1 skips wait_for_rcp_salt and
 * parks in wait_for_vector. Do NOT try to (re)seed it from here: a runtime
 * mcrr p7,#8,…,c1 with the salt already valid stalls core 0 forever
 * (device-verified: wedged un-haltable mid-mcrr, breadcrumb 0x11). The one
 * state where core 1 does wait for a salt is debugger-induced (openocd
 * per-core resets clear core 1's RCP while core 0's stays valid); that
 * shows up as a bounded SG_ERR_INTERNAL below and a physical POR fixes it. */

int tz_core1_launch_ns(uintptr_t ns_vtor, uintptr_t ns_entry,
                       uintptr_t ns_stack_top) {
    /* Hard-reset core 1 (PSM FRCE_OFF pulse; readback fences the APB store
     * buffer) to a known bootrom state, killing any previous payload. */
    hw_set_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    while (!(psm_hw->frce_off & PSM_FRCE_OFF_PROC1_BITS)) tight_loop_contents();
    core1_fifo_drain();
    hw_clear_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    core1_running = false;

    uint32_t v;
    if (!core1_fifo_pop(&v)) return SG_ERR_INTERNAL;

    if (ns_entry == 0) return SG_OK; /* parked in the bootrom wait loop */

    core1_ns.ns_vtor      = ns_vtor;
    core1_ns.ns_entry     = ns_entry;
    core1_ns.ns_stack_top = ns_stack_top;

    /* Bootrom mailbox launch protocol (datasheet §5.3; same sequence as the
     * SDK's multicore_launch_core1_raw). We launch core 1 into the SECURE
     * trampoline — monitor VTOR, monitor Secure stack — not straight to the
     * NS entry: a plain bootrom `blx` into an NS address would be an illegal
     * S->NS transition. The trampoline does the transition properly. Each
     * word is echoed; a wrong echo restarts the sequence. Bounded overall. */
    const uint32_t seq[] = {
        0, 0, 1,
        scb_hw->vtor,                                        /* trampoline VTOR */
        (uintptr_t)&core1_tramp_stack[count_of(core1_tramp_stack)],
        (uintptr_t)core1_ns_trampoline | 1u,                 /* thumb bit */
    };
    uint32_t seq_i = 0;
    for (uint32_t attempts = 64; seq_i < count_of(seq); attempts--) {
        if (!attempts) return SG_ERR_INTERNAL;
        uint32_t cmd = seq[seq_i];
        if (!cmd) {
            core1_fifo_drain();
            __sev(); /* core 1 may be waiting for FIFO space via WFE */
        }
        if (!core1_fifo_push(cmd)) return SG_ERR_INTERNAL;
        uint32_t resp;
        if (!core1_fifo_pop(&resp)) return SG_ERR_INTERNAL;
        seq_i = (cmd == resp) ? seq_i + 1 : 0;
    }
    core1_running = true;
    return SG_OK;
}

int main(void) {
    /* Entered by the bootrom after verifying the monitor's signature (which
     * covers .ns_manifest). Order matters: the NS image is authenticated
     * and keys come out of OTP (SW_LOCK ratchet closing behind them)
     * BEFORE anything Non-secure exists or runs. */
    tz_diag.magic = TZ_DIAG_MAGIC;
    led_init();
    led_set(true);
    diag_stage(TZ_STAGE_ENTERED);       /* (A) */
    /* Route configurable faults to their specific handlers instead of
     * escalating everything to HardFault, so the diag record (and LED
     * read-out) carries the exact fault class. NS bus/secure faults target
     * these Secure handlers because BFHFNMINS=0. */
    m33_hw->shcsr |= M33_SHCSR_SECUREFAULTENA_BITS | M33_SHCSR_BUSFAULTENA_BITS
                   | M33_SHCSR_USGFAULTENA_BITS | M33_SHCSR_MEMFAULTENA_BITS;
    verify_ns_image();        /* halts (kind=NS_HASH_MISMATCH) on mismatch */
    diag_stage(TZ_STAGE_NS_VERIFIED);   /* (B) */
    monitor_derive_keys();
    diag_stage(TZ_STAGE_KEYS_DERIVED);  /* (C) */
    monitor_aon_init();
    partition_configure();
    diag_stage(TZ_STAGE_PARTITIONED);   /* (D) */
    led_set(true);            /* (E) solid on — about to blxns into NS */
    ns_launch();
}
