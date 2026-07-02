# TrustZone-partitioned R2P2 (RP2350) — design sketch

Status: **sketch / not built yet**. This directory holds the shared contract
between the two firmware images of a Secure/Non-secure split R2P2:

- `include/r2p2_sg_api.h` — the Secure Gateway (veneer) API, compiled into
  both images
- `monitor/memmap_monitor_s.ld` — linker script for the Secure monitor image
- `ns/memmap_r2p2_ns.ld` — linker script for the Non-secure R2P2 image
  (derived from `../cmake/memmap_rp2350.ld`)

Targets RP2350 Arm (Cortex-M33) only: TrustZone-M does not exist on the
Hazard3 RISC-V cores or on RP2040. Built against pico-sdk 2.2.0.

## Goal

User Ruby code (and the whole VM/shell/filesystem stack) runs Non-secure.
A small signed Secure monitor owns OTP, TRNG, SHA-256 and all long-term key
material, and exposes a key-handle crypto API through CMSE veneers. A fully
compromised NS runtime can *use* keys but never *read* them. In particular,
`Machine.read_memory` against Secure addresses takes a SecureFault instead
of leaking keys.

## Memory map (pico2, 4 MiB flash / 520 KiB SRAM)

### Flash

| Range                     | Size     | Owner | Contents                              |
|---------------------------|----------|-------|---------------------------------------|
| 0x10000000 – 0x1000EFFF   | 60 KiB   | S     | Monitor code + rodata (XIP)           |
| 0x1000F000 – 0x1000FFFF   | 4 KiB    | S+NSC | `.gnu.sgstubs` veneers (fixed addr)   |
| 0x10010000 – 0x1033FFFF   | 3264 KiB | NS    | R2P2 firmware (VM, gems, shell)       |
| 0x10340000 – 0x103FFFFF   | 768 KiB  | NS    | FAT filesystem (existing offset)      |

The filesystem offset matches today's `FLASH_TARGET_OFFSET=0x00340000`
(`../cmake/CMakeLists.txt`), so the on-flash FS layout is unchanged. NS code
reads the FS via XIP as today; NS *writes* go through the bootrom's
`checked_flash_op` NS API validated against a partition table that marks
only the FS partition `PICOBIN_PARTITION_PERMISSION_NS_W`. NS therefore
cannot reflash the monitor or its own firmware image.

### RAM

RP2350's main 512 KiB SRAM (banks 0–7) is **word-striped**
(`SRAM_STRIPED_BASE`..`END` in the SDK address map), so ACCESSCTRL's
per-bank gates cannot carve a contiguous Secure region out of it. The two
4 KiB scratch banks SRAM8/SRAM9 are direct-mapped and individually gateable.

| Range                     | Size    | Owner | Contents                                  |
|---------------------------|---------|-------|-------------------------------------------|
| 0x20000000 – 0x2007FFFF   | 512 KiB | NS    | R2P2 as today (heap_pool, stacks, .data)  |
| 0x20080000 – 0x20081FFF   | 8 KiB   | S     | Monitor .data/.bss/stack (SRAM8+SRAM9)    |

Consequences:

- The VM heap does not shrink at all.
- Core 1's NS stack moves out of SCRATCH_X into main RAM (handled in
  `ns/memmap_r2p2_ns.ld`); SDK `.scratch_x.*`/`.scratch_y.*` input sections
  are remapped to main RAM.
- 8 KiB is tight for runtime ECDSA verify (`sg_verify_mrb`). mbedTLS needs
  tuning (`MBEDTLS_ECP_WINDOW_SIZE`, `MBEDTLS_MPI_MAX_SIZE`, no ECP
  fixed-point optimization). At *boot* the monitor may freely use main RAM
  as scratch (verify NS image, derive keys) as long as it wipes it before
  configuring the SAU and jumping to NS. If runtime verify does not fit,
  fallback options: move `sg_verify_mrb` workspace policy to boot-time-only
  verification, or (costly) promote striped banks 4–7 to Secure and shrink
  the NS heap by 256 KiB.

## SAU plan (8 regions available; background = Secure once enabled)

| # | Range                     | Attr   | Purpose                                   |
|---|---------------------------|--------|-------------------------------------------|
| 0 | 0x1000F000 – 0x1000FFFF   | S+NSC  | veneer gateway (`.gnu.sgstubs`)           |
| 1 | 0x10010000 – 0x103FFFFF   | NS     | NS firmware + filesystem (XIP reads)      |
| 2 | 0x20000000 – 0x2007FFFF   | NS     | main SRAM                                 |
| 3 | 0x40000000 – 0x5FFFFFFF   | NS     | APB/AHB peripherals (bus-filtered by ACCESSCTRL per peripheral) |
| 4 | 0xD0000000 – 0xDFFFFFFF   | NS     | SIO NS alias etc. — TODO(datasheet §10):  |
|   |                           |        | confirm what the fixed IDAU already marks |
|   |                           |        | NS/exempt before spending SAU regions     |

Everything not covered (monitor flash, SRAM8/9, PPB) falls into the Secure
background. TODO(datasheet §10.9): reconcile with RP2350's fixed IDAU —
some ranges (ROM, SIO non-secure alias at 0xd0020000, PPB NS alias) have
hardwired attributes and may not need SAU regions at all.

## ACCESSCTRL assignment (monitor writes these at boot, then sets LOCK)

- **Stays Secure-only** (default): `OTP`, `TRNG`, `SHA256`, `CLOCKS`,
  `XOSC`, `ROSC`, `PLL_SYS`, `PLL_USB`, `POWMAN`, `TICKS`, `RSM`, `RESETS`,
  `XIP_CTRL`, `XIP_QMI`, `XIP_AUX`, `BUSCTRL`, `SYSCFG`, `PADS_QSPI`,
  `SRAM8`, `SRAM9`, `CORESIGHT_*`, `TIMER1` (reserved for monitor use).
- **Granted NS** (`*_NSP`): `SRAM0`–`SRAM7`, `XIP_MAIN`, `DMA`, `USBCTRL`,
  `PIO0`–`PIO2`, `IO_BANK0`, `PADS_BANK0`, `ADC0`, `HSTX`, `I2C0`, `I2C1`,
  `PWM`, `SPI0`, `SPI1`, `TIMER0`, `UART0`, `UART1`, `WATCHDOG` (an NS
  watchdog reboot just re-enters secure boot — acceptable), `SYSINFO`,
  `TBMAN`.
- **GPIO**: `gpio_assign_to_ns()` for all user pins; QSPI pads stay Secure.
- **IRQs**: `irq_assign_to_ns()` (NVIC ITNS) for every NS peripheral's IRQ;
  NS interrupts then vector directly to the NS vector table, no trampolines.
- **DMA**: NS gets the DMA block, but the monitor must program per-channel
  `SECCFG_CHx` (+ `SECCFG_IRQ*`, MPU-for-DMA if used) so NS-programmed
  channels issue NS bus transactions only. Without this, NS DMA is a hole
  through the SAU (SAU filters CPU accesses only).

## Bootrom NS API enablement (monitor calls at boot)

All bootrom NS APIs default to *disabled*. The monitor enables exactly:

- `rom_set_ns_api_permission(BOOTROM_NS_API_checked_flash_op, true)` — FS writes
- `rom_set_ns_api_permission(BOOTROM_NS_API_flash_runtime_to_storage_addr, true)`
- `rom_set_ns_api_permission(BOOTROM_NS_API_get_sys_info, true)` (convenience)
- `reboot` — optional, or route through a veneer for policy
- **Not** `otp_access`, **not** `secure_call` (we use CMSE veneers instead)

## Build flow (two images)

1. **Monitor** (new small CMake project, `PICO_SECURE=1`, default
   `rp2350-arm-s` platform): compiled with `-mcmse` (already the SDK
   toolchain default); linked with `monitor/memmap_monitor_s.ld` and
   `-Wl,--cmse-implib,--out-implib=r2p2_sg_implib.o`. On rebuilds pass the
   previous implib via `--in-implib` to keep veneer addresses stable.
   Signed with `pico_sign_binary()`; IMAGE_DEF `EXE_SECURITY=S`.
2. **NS R2P2**: today's build minus S-only runtime-init stages (clocks/PLL
   setup — the monitor owns clocks; SDK runtime-init is weak-symbol based,
   so these are overridable). Linked with `ns/memmap_r2p2_ns.ld` and
   `r2p2_sg_implib.o`. IMAGE_DEF `EXE_SECURITY=NS`, UF2 family
   `RP2350_ARM_NS`. There is no `rp2350-arm-ns` SDK platform — expect to
   build under `rp2350-arm-s` and patch, or write a platform file.
3. **Partition table** with the FS partition marked NS_R/NS_W; embedded via
   `pico_embed_pt_in_binary` / picotool.
4. Boot: bootrom verifies + enters monitor (S) → monitor verifies/chains the
   NS image, derives keys from OTP, wipes scratch, configures SAU +
   ACCESSCTRL(+LOCK) + ITNS + DMA SECCFG + GPIO NS masks, enables the
   bootrom NS APIs above → sets NS VTOR/MSP_NS → `blxns` into NS reset.

## Known open items

- Core 1: bootrom launch protocol is Secure-side; NS needs an
  `sg_launch_core1_ns()` veneer (see header TODO) or PSG/pitchdetector
  stay disabled in the first cut. `ACCESSCTRL_FORCE_CORE_NS` can pin
  core 1 NS at the bus level.
- `Machine.deep_sleep` / vreg / clock dialing touch S-only peripherals →
  needs an `sg_deep_sleep()` veneer or gets dropped initially.
- `sg_verify_mrb` guarantees signature validity of the buffer *at the time
  of the call* — it is policy attestation, not NS memory integrity (NS can
  modify the buffer after the call; that is inherent and accepted: the
  threat model protects keys, not NS control flow).
- Slot→OTP row mapping and per-slot key policy live in the monitor's
  `sg_config` (not in this header) so NS rebuilds can't change policy.
