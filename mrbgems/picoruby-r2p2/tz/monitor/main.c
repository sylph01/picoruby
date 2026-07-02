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
#include "boot/bootrom_constants.h"
#include "hardware/structs/sau.h"
#include "hardware/structs/accessctrl.h"
#include "hardware/structs/nvic.h"
#include "hardware/structs/m33.h"
#include "hardware/structs/dma.h"
#include "hardware/regs/m33.h"
#include "hardware/regs/accessctrl.h"
#include "hardware/regs/dma.h"
#include "hardware/regs/intctrl.h"

#include "../include/r2p2_sg_api.h"

/* ---- memory map (single source of truth: tz/README.md; must match the
 *      linker scripts) ---------------------------------------------------- */

#define TZ_SG_NSC_BASE    0x1000f000u  /* .gnu.sgstubs in memmap_monitor_s.ld */
#define TZ_SG_NSC_LAST    0x1000ffffu
#define TZ_NS_FLASH_BASE  0x10010000u  /* NS image + filesystem, to end of 4 MiB flash */
#define TZ_NS_FLASH_LAST  0x103fffffu
#define TZ_NS_RAM_BASE    0x20000000u  /* all 512 KiB striped SRAM */
#define TZ_NS_RAM_LAST    0x2007ffffu

/* All ACCESSCTRL registers except GPIO_NSMASK* require this password in the
 * upper half of the write data; writes without it bus-fault (§10.6). */
#define AC_PASSWORD 0xacce0000u

/* Manager bits (DBG/DMA/CORE1/CORE0) + all four security levels. Peripheral
 * registers reset with NSP/NSU clear, memory devices reset to 0xff. */
#define AC_ALLOW_ALL     (AC_PASSWORD | 0xffu)
#define AC_SECURE_ONLY   (AC_PASSWORD | (0xffu & ~(ACCESSCTRL_UART0_NSP_BITS | ACCESSCTRL_UART0_NSU_BITS)))

/* DMA channels handed to NS. Channel security locks at first use until DMA
 * block reset, so this is a boot-time-only assignment. */
#define TZ_NS_DMA_CHANNELS 12u

/* IRQs retargeted to the NS vector table via NVIC ITNS. Everything an NS
 * peripheral can raise; SecureFault/faults stay Secure (AIRCR.BFHFNMINS=0,
 * the reset default, is deliberately left alone). */
static const uint8_t tz_ns_irqs[] = {
    TIMER0_IRQ_0, TIMER0_IRQ_1, TIMER0_IRQ_2, TIMER0_IRQ_3,
    PWM_IRQ_WRAP_0, PWM_IRQ_WRAP_1,
    DMA_IRQ_0, DMA_IRQ_1, DMA_IRQ_2, DMA_IRQ_3,
    USBCTRL_IRQ,
    PIO0_IRQ_0, PIO0_IRQ_1, PIO1_IRQ_0, PIO1_IRQ_1, PIO2_IRQ_0, PIO2_IRQ_1,
    IO_IRQ_BANK0,
    SPI0_IRQ, SPI1_IRQ,
    UART0_IRQ, UART1_IRQ,
    ADC_IRQ_FIFO,
    I2C0_IRQ, I2C1_IRQ,
};

/* ---- key material ------------------------------------------------------- */

/* Filled by monitor_derive_keys(), lives only in Secure SRAM8/9 .bss. */
typedef struct {
    uint8_t device_root[32];   /* HKDF-extracted from OTP key page          */
    uint8_t gateway_psk[32];   /* provisioned PSK, read from its OTP page   */
} tz_keystore_t;

static tz_keystore_t keystore;

static void monitor_derive_keys(void) {
    /* TODO:
     *  - rom_func_otp_access() ECC reads of the key rows for
     *    SG_SLOT_DEVICE_ROOT / SG_SLOT_GATEWAY_PSK into `keystore`
     *  - HKDF-Extract via the SHA-256 accelerator (monitor owns it)
     *  - ratchet OTP_SW_LOCKx for those pages to inaccessible — the tier-2
     *    move kept as defense in depth; even Secure code can't reread the
     *    master pages until reset
     */
}

/* ---- partition configuration -------------------------------------------- */

static void sau_region(uint32_t region, uint32_t base, uint32_t last, bool nsc) {
    sau_hw->rnr = region;
    sau_hw->rbar = base & M33_SAU_RBAR_BADDR_BITS;
    sau_hw->rlar = (last & M33_SAU_RLAR_LADDR_BITS)   /* 32-byte granules */
                 | (nsc ? M33_SAU_RLAR_NSC_BITS : 0)
                 | M33_SAU_RLAR_ENABLE_BITS;
}

static void partition_configure(void) {
    /* SAU: three regions; background stays Secure (monitor flash, SRAM8/9).
     * Region 7 (bootrom) untouched. SAU is already enabled by the bootrom,
     * but reasserting CTRL is harmless and self-documenting. */
    sau_region(0, TZ_SG_NSC_BASE, TZ_SG_NSC_LAST, true);   /* veneers: S+NSC */
    sau_region(1, TZ_NS_FLASH_BASE, TZ_NS_FLASH_LAST, false); /* NS code+FS  */
    sau_region(2, TZ_NS_RAM_BASE, TZ_NS_RAM_LAST, false);     /* NS RAM      */
    sau_hw->ctrl = M33_SAU_CTRL_ENABLE_BITS;               /* ALLNS=0 */

    /* ACCESSCTRL, memory side: strip NS from the monitor's SRAM banks.
     * They reset to 0xff (NS-accessible), and the SAU only filters the CPU —
     * without this, an NS-programmed bus master could still reach them. */
    accessctrl_hw->sram[8] = AC_SECURE_ONLY;
    accessctrl_hw->sram[9] = AC_SECURE_ONLY;

    /* ACCESSCTRL, peripheral side: grant NS to everything R2P2 drives.
     * Peripherals not listed keep their Secure-only reset value: OTP, TRNG,
     * SHA256, CLOCKS, XOSC, ROSC, PLLs, POWMAN, TICKS, RESETS(*), XIP_QMI,
     * XIP_CTRL, XIP_AUX, BUSCTRL, SYSCFG, PADS_QSPI, TIMER1, CORESIGHT_*.
     * (*) RESETS access rides on the per-peripheral bits (§10.6.2), so NS
     * can still reset-cycle its own peripherals. */
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

    /* GPIO: user pins to NS (both domains), QSPI pads stay Secure-only.
     * GPIO_NSMASK is the one ACCESSCTRL register with no password. Pico 2
     * (RP2350A) has GPIOs 0-29 in bank 0; USB DP/DM are NSMASK1 bits 30/31
     * per §10.6.1 and must be NS for TinyUSB. */
    accessctrl_hw->gpio_nsmask[0] = 0x3fffffffu;
    accessctrl_hw->gpio_nsmask[1] = 0xc0000000u;

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

static void __attribute__((noreturn)) ns_launch(void) {
    const uint32_t *ns_vtor = (const uint32_t *)TZ_NS_FLASH_BASE;

    /* NS banked SCS via the PPB_NONSEC alias: vector table + main stack. */
    m33_ns_hw->vtor = (uintptr_t)ns_vtor;
    __asm volatile ("msr msp_ns, %0" :: "r" (ns_vtor[0]));

    /* Let NS use the FPU: NSACR grants CP10/CP11 to NS, CPACR_NS enables
     * them within NS (R2P2 builds with hard float). */
    m33_hw->nsacr |= M33_NSACR_CP10_BITS | M33_NSACR_CP11_BITS;
    m33_ns_hw->cpacr |= M33_CPACR_CP10_BITS | M33_CPACR_CP11_BITS;

    /* AIRCR defaults kept: BFHFNMINS=0 (bus/hard faults target Secure),
     * SYSRESETREQS=0 (NS may request system reset — the watchdog is NS
     * anyway and any reset re-enters secure boot).
     * TODO: seal the Secure stacks (store 0xfef5eda5 at the stack limits,
     * ARM stack-sealing recommendation) in crt0/startup.
     * TODO(phase 2, PSG/pitchdetector): sg_launch_core1_ns veneer with
     * ACCESSCTRL FORCE_CORE_NS.CORE1 so core 1 runs NS-only. */

    /* cmse_nonsecure_call: the compiler clears non-argument registers and
     * emits BLXNS; the target address needs its LSB clear for the NS
     * transition, which GCC handles via the function-pointer bit-clear. */
    ns_reset_fn ns_reset = (ns_reset_fn)(uintptr_t)ns_vtor[1];
    ns_reset();
    __builtin_unreachable();
}

int main(void) {
    /* Entered by the bootrom after signature verification of the combined
     * monitor+NS image; interrupts still masked by crt0 until runtime init.
     * Order matters: keys come out of OTP and the SW_LOCK ratchet closes
     * BEFORE anything Non-secure exists. */
    monitor_derive_keys();
    partition_configure();
    ns_launch();
}
