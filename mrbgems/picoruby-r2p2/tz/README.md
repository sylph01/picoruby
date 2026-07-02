# TrustZone-partitioned R2P2 (RP2350) — design sketch

Status: **sketch / not built yet**. This directory holds the shared contract
between the two firmware images of a Secure/Non-secure split R2P2:

- `include/r2p2_sg_api.h` — the Secure Gateway (veneer) API, compiled into
  both images
- `monitor/main.c` — monitor skeleton: key derivation, SAU/ACCESSCTRL/ITNS/
  DMA partition setup, NS handoff via `blxns`
- `monitor/memmap_monitor_s.ld` — linker script for the Secure monitor image
- `ns/memmap_r2p2_ns.ld` — linker script for the Non-secure R2P2 image
  (derived from `../cmake/memmap_rp2350.ld`)

## Phase-1 decisions (recorded 2026-07-02)

1. **Monitor executes XIP from Secure flash.** The phase-1 threat model is a
   compromised NS runtime, not a physical flash-swap attacker (the white
   paper's "never execute secure code from flash" tip targets the latter).
   Revisit with encrypted boot / SRAM packaging if physical attacks enter
   the threat model.
2. **The bootrom verifies everything at boot.** Monitor + NS image are
   packaged and signed as ONE unit: the monitor's IMAGE_DEF signature covers
   both flash regions. Note the bootrom cannot launch an `EXE_SECURITY=NS`
   image (the `rp2350_arm_ns` family is "not directly bootable", datasheet
   §5.9), so `chain_image()` is not used; the monitor performs the NS entry
   itself. Consequence: no signature-verification code in the monitor at
   all — no mbedTLS.
3. **`sg_verify_mrb` is deferred to phase 2** and returns
   `SG_ERR_NOT_PERMITTED` until the verification story (ECDSA vs HMAC seal)
   is settled.
4. **AEAD is ChaCha20-Poly1305** (constant-time in software, no AES
   hardware on RP2350, small code). With HKDF over the hardware SHA-256,
   the monitor's whole crypto stack is a few KiB of freestanding code.

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
- With phase-1 decisions (no mbedTLS, ChaCha20-Poly1305 + HKDF over the
  hardware SHA-256), 8 KiB of data/stack RAM is comfortable. At *boot* the
  monitor may additionally use main RAM as scratch (key derivation) as long
  as it wipes it before configuring the SAU and jumping to NS. If phase 2
  adds runtime ECDSA for `sg_verify_mrb`, revisit: tuned mbedTLS needs
  ~4-6 KiB of stack, which is the whole budget.

## IDAU (verified, datasheet §10.2.2)

The IDAU is a hardwired decode with no configuration. Final attribution is
`max(SAU, IDAU)` in the order S > NSC > NS, unless the IDAU says Exempt:

| Range                   | Contents        | IDAU attribute                     |
|-------------------------|-----------------|------------------------------------|
| 0x00000000 – 0x000042FF | Arm boot ROM    | Exempt                             |
| 0x00004300 – 0x00007DFF | USB/RISC-V boot | NS (ifetch), Exempt (load/store)   |
| 0x00007E00 – 0x00007FFF | Bootrom SGs     | Secure + NSC                       |
| 0x10000000 – 0x1FFFFFFF | XIP             | **Non-secure** (divide with SAU)   |
| 0x20000000 – 0x20081FFF | SRAM            | **Non-secure** (divide with SAU)   |
| 0x40000000 – 0x4FFFFFFF | APB peripherals | Exempt                             |
| 0x50000000 – 0x5FFFFFFF | AHB peripherals | Exempt                             |
| 0xD0000000 – 0xDFFFFFFF | SIO             | Exempt (banked by bus security)    |

Consequences:

- Monitor flash and SRAM8/9 are Secure simply by NOT being covered by any
  NS SAU region (SAU background is Secure).
- Never spend SAU regions on peripherals or SIO — Exempt means both worlds
  reach them and ACCESSCTRL alone does the filtering. (Instruction fetch
  from peripheral space is physically disconnected.)
- The bootrom exits into user code with the SAU **already enabled** and
  **SAU region 7 programmed over the entire bootrom** — region 7 belongs to
  the bootrom; the monitor uses regions 0–6.

## SAU plan (regions 0–6 available)

| # | Range                     | Attr   | Purpose                              |
|---|---------------------------|--------|--------------------------------------|
| 0 | 0x1000F000 – 0x1000FFFF   | S+NSC  | veneer gateway (`.gnu.sgstubs`)      |
| 1 | 0x10010000 – 0x103FFFFF   | NS     | NS firmware + filesystem (XIP reads) |
| 2 | 0x20000000 – 0x2007FFFF   | NS     | main SRAM                            |
| 7 | (bootrom's, do not touch) | NS     | entire bootrom, set by the bootrom   |

Regions 3–6 spare. Everything uncovered (monitor flash, SRAM8/9, PPB) is
Secure background.

## ACCESSCTRL assignment (monitor writes these at boot, then sets LOCK)

Verified semantics (datasheet §10.6): every register except `GPIO_NSMASK*`
requires the password `0xacce` in the upper 16 bits of the write data
(writes without it bus-fault). Bits are manager enables (DBG/DMA/CORE1/
CORE0) × security-level enables (SP/SU/NSP/NSU). **Reset defaults differ**:
memory devices (`ROM`, `SRAM*`, `XIP_MAIN`) reset to `0xff` (NS-accessible),
peripherals reset with NSP/NSU clear (Secure-only).

- **Revoke NS** (they default open!): `SRAM8`, `SRAM9` — without this, an
  NS-programmed bus master could reach monitor RAM; the SAU only filters
  CPU accesses.
- **Stays Secure-only** (peripheral default): `OTP`, `TRNG`, `SHA256`,
  `CLOCKS`, `XOSC`, `ROSC`, `PLL_SYS`, `PLL_USB`, `POWMAN`, `TICKS`, `RSM`,
  `XIP_CTRL`, `XIP_QMI`, `XIP_AUX`, `BUSCTRL`, `SYSCFG`, `PADS_QSPI`,
  `CORESIGHT_*`, `TIMER1` (reserved for monitor use).
- **Granted NS**: `SRAM0`–`SRAM7` + `XIP_MAIN` (already default), `DMA`,
  `USBCTRL`, `PIO0`–`PIO2`, `IO_BANK0`, `PADS_BANK0`, `ADC0`, `HSTX`,
  `I2C0`, `I2C1`, `PWM`, `SPI0`, `SPI1`, `TIMER0`, `UART0`, `UART1`,
  `WATCHDOG` (an NS watchdog reboot just re-enters secure boot —
  acceptable), `SYSINFO`, `TBMAN`. RESETS access rides on the
  per-peripheral bits, so NS can reset-cycle its own peripherals.
- **GPIO**: `GPIO_NSMASK0` for all user pins; QSPI pads stay Secure; USB
  DP/DM are NSMASK1 bits 30/31 and must be NS for TinyUSB.
- **IRQs**: NVIC ITNS for every NS peripheral's IRQ; NS interrupts then
  vector directly to the NS vector table, no trampolines.
- **DMA**: per-channel `SECCFG_CHx` (LOCK/S/P bits). All channels reset to
  Secure+Privileged; a channel's level **locks at first use** until DMA
  block reset. Monitor sets the NS channels to NSP+LOCK at boot, plus
  `SECCFG_IRQ0/1` at NS so NS sees its channels' interrupt state. Without
  this, NS DMA would be a hole through the SAU.
- Finish with the `LOCK` register (CORE0/CORE1/DMA; one-way until reset).
  Leave DEBUG unlocked during bring-up, lock it for production.

## Bootrom NS API enablement (monitor calls at boot)

All bootrom NS APIs default to *disabled*. The monitor enables exactly:

- `rom_set_ns_api_permission(BOOTROM_NS_API_checked_flash_op, true)` — FS writes
- `rom_set_ns_api_permission(BOOTROM_NS_API_flash_runtime_to_storage_addr, true)`
- `rom_set_ns_api_permission(BOOTROM_NS_API_get_sys_info, true)` (convenience)
- `reboot` — optional, or route through a veneer for policy
- **Not** `otp_access`, **not** `secure_call` (we use CMSE veneers instead)

## Build flow (two builds, one signed unit)

1. **Monitor** (new small CMake project, `PICO_SECURE=1`, default
   `rp2350-arm-s` platform): compiled with `-mcmse` (already the SDK
   toolchain default); linked with `monitor/memmap_monitor_s.ld` and
   `-Wl,--cmse-implib,--out-implib=r2p2_sg_implib.o`. On rebuilds pass the
   previous implib via `--in-implib` to keep veneer addresses stable
   (matters for developing the NS image against a flashed monitor; moot
   when both are reflashed together).
2. **NS R2P2**: today's build minus S-only runtime-init stages (clocks/PLL
   setup — the monitor owns clocks; SDK runtime-init is weak-symbol based,
   so these are overridable). Linked with `ns/memmap_r2p2_ns.ld` and
   `r2p2_sg_implib.o`. IMAGE_DEF `EXE_SECURITY=NS`, UF2 family
   `RP2350_ARM_NS`. There is no `rp2350-arm-ns` SDK platform — expect to
   build under `rp2350-arm-s` and patch, or write a platform file.
3. **Packaging**: the two binaries are combined and signed as one unit —
   the monitor's IMAGE_DEF (`EXE_SECURITY=S`) signature covers
   0x10000000..NS image end, so the bootrom verifies both at boot. The
   bootrom cannot launch NS images (`rp2350_arm_ns` is "not directly
   bootable"), so `chain_image()` is not used.
4. **Partition table** with the FS partition marked NS_R/NS_W; embedded via
   `pico_embed_pt_in_binary` / picotool.
5. Boot: bootrom verifies the combined image + enters the monitor (S) →
   monitor derives keys from OTP + ratchets SW_LOCK, configures SAU +
   ACCESSCTRL(+LOCK) + ITNS + DMA SECCFG + GPIO NS masks, enables the
   bootrom NS APIs above → sets VTOR_NS/MSP_NS + NSACR (NS FPU) → `blxns`
   into the NS reset handler. See `monitor/main.c`.

## Secure boot enable (OTP, irreversible — datasheet §10.5)

For reference, the production one-time procedure: program ≥1 public key
fingerprint at `BOOTKEY0_0`, set `BOOT_FLAGS1.KEY_VALID` (+`KEY_INVALID`
for unused slots), disable debug via `CRIT1.DEBUG_DISABLE`/debug key,
optionally enable glitch detectors (`CRIT1.GLITCH_DETECTOR_ENABLE`),
disable unused boot paths in `BOOT_FLAGS0`, then `CRIT1.SECURE_BOOT_ENABLE`.
Development boards skip this: the partition still works unsigned; secure
boot is what makes the monitor's presence non-bypassable.

## NS runtime-init trimming (`ns/runtime_init_ns.c`, `ns/ns_build.cmake`)

The stock SDK runtime init assumes it owns the whole chip. Stage-by-stage
disposition for the NS image (SDK stage order):

| Stage                              | NS disposition | Why |
|------------------------------------|----------------|-----|
| `BOOTROM_RESET` (global)           | **skip** (define) | `bootrom_state_reset` is Arm-S-only (§5.4.8) — NS ROM-table lookup fails at boot; it would also revoke the monitor's NS API grants. Monitor does it. |
| `PER_CORE_BOOTROM_RESET`           | **skip** (define) | same API |
| `EARLY_RESETS`                     | **override** | stock masks ~all RESETS bits; Secure-only bits are unwritable from NS and waiting on their RESET_DONE hangs. Override reset-cycles only `TZ_NS_RESETS_MASK`. |
| `USB_POWER_DOWN`                   | unchanged | USBCTRL is NS-granted |
| `PER_CORE_ENABLE_COPROCESSORS`     | unchanged | CPACR is banked (hits CPACR_NS); works because monitor NSACR grants CP0/CP4/CP10/CP11 |
| `CLOCKS`                           | **override** | CLOCKS is Secure-only, not even readable. Override reports the contract frequencies (`r2p2_tz_config.h`) via `clock_set_reported_hz()` so `clock_get_hz()` stays correct; no tick start (TICKS is Secure, monitor started them). |
| `POST_CLOCK_RESETS`                | **override** (empty) | stock waits on RESET_DONE for all bits incl. Secure-only ones |
| `RP2040_GPIO_IE_DISABLE`           | unchanged | compiles empty on RP2350 |
| `SPIN_LOCKS_RESET`                 | unchanged | RP2350 defaults to software spin locks (erratum); NS SIO also has its own spinlock bank |
| `INSTALL_RAM_VECTOR_TABLE`         | unchanged | SCB->VTOR banked → VTOR_NS |
| stack guard (MPU)                  | unchanged | MPU banked → MPU_NS |

## NS build: gem impact

Gems that must change (or go) to fit the security model:

| Gem | Impact | What changes |
|-----|--------|--------------|
| `picoruby-machine` | **modify** | `Machine.deep_sleep`/`sleep` touch XOSC/ROSC dormancy, CLOCKS, VREG/POWMAN — all Secure-only → `sg_deep_sleep()` veneer (phase 2) or disabled. `Machine.using_usb?`-style paths, unique-id via bootrom `get_sys_info` (NS API enabled) keep working. `Machine.read_memory` of Secure addresses now SecureFaults (hardware-enforced; consider removing anyway for UX). Time-of-day via `pico_aon_timer` sits on POWMAN (Secure-only) → needs an `sg_time_*` veneer or NS timekeeping on TIMER0 — open decision. |
| `picoruby-rng` | **modify** | `get_rand_32()` → RP2350 TRNG, which is Secure-only and faults from NS. TZ build calls `sg_random_bytes()` instead (the fresh non-TZ fix stays for stock builds). |
| `picoruby-filesystem-fat` | **modify** | `flash_disk.c` `flash_range_program/erase` → bootrom `checked_flash_op` NS API (validated against the NS_W partition). |
| `picoruby-littlefs` | **modify** | same change in `flash_hal.c` |
| `picoruby-mbedtls` | **modify** | `mbedtls_hardware_poll` → `get_rand_64` → TRNG faults from NS; re-point at `sg_random_bytes()`. Raw-key `Cipher` API unchanged by design. |
| `picoruby-psg` | **cut (phase 1)** | runs its driver on core 1; NS cannot launch core 1 until `sg_launch_core1_ns()` exists (phase 2) |
| `picoruby-pitchdetector` | **audit/cut** | ADC+DMA fine per se; cut with psg if it shares the core-1 pattern |
| `picoruby-cyw43` / `-net` / `-socket` / `-ble` (pico2_w) | **defer/audit** | driver itself uses PIO/DMA/GPIO (all NS-granted incl. NSMASK bits), but lwIP/mbedTLS pull `pico_rand` → TRNG fault. Needs an NS `get_rand_*` replacement backed by `sg_random_bytes()` (link-level override), then re-audit. Phase 1 targets plain pico2. |
| `picoruby-watchdog` | unchanged | WATCHDOG NS-granted; tick already running (monitor) |
| `picoruby-gpio/-uart/-i2c/-spi/-adc/-pwm/-pio/-irq/-usb-hid/-io-console` | unchanged | peripherals NS-granted, IRQs in ITNS |
| shell / require / sandbox / VM gems | unchanged | pure software |

## Known open items

- Core 1: bootrom launch protocol is Secure-side; NS needs an
  `sg_launch_core1_ns()` veneer (see header TODO) or PSG/pitchdetector
  stay disabled in the first cut. `ACCESSCTRL_FORCE_CORE_NS` pins core 1
  NS at the bus level — the datasheet explicitly endorses "all Secure
  services run on core 0" schemes (§10.6.2).
- Secure stack sealing (store `0xfef5eda5` at the Secure stack limits, per
  Arm's TrustZone-M recommendations) belongs in the monitor crt0/startup.
- `Machine.deep_sleep` / vreg / clock dialing touch S-only peripherals →
  needs an `sg_deep_sleep()` veneer or gets dropped initially.
- `sg_verify_mrb` guarantees signature validity of the buffer *at the time
  of the call* — it is policy attestation, not NS memory integrity (NS can
  modify the buffer after the call; that is inherent and accepted: the
  threat model protects keys, not NS control flow).
- Slot→OTP row mapping and per-slot key policy live in the monitor's
  `sg_config` (not in this header) so NS rebuilds can't change policy.
