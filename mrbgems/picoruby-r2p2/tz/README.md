# TrustZone-partitioned R2P2 (RP2350) — design sketch

Status: **phase 1 working on hardware** (Pico 2, SDK 2.2.0, arm-none-eabi-gcc
14.2; verified 2026-07-03). The combined image boots: monitor verifies the
NS image (SHA-256 vs `.ns_manifest`), configures SAU/ACCESSCTRL/ITNS/DMA,
and `blxns`es into a Non-secure mruby VM running the full R2P2 shell over
USB CDC. Field-verified veneer round-trips: `sg_random_bytes` (RNG gem),
`sg_flash_erase`/`sg_flash_program`/cache flush (FAT filesystem format at
boot + runtime `File` write/read), `sg_sha256` (monitor-side NS verify).
Build: monitor standalone (`monitor/CMakeLists.txt`), NS via
`R2P2_TRUSTZONE=1 rake r2p2:picoruby:pico2:prod` (see `ns/ns_build.cmake`),
then `rake r2p2:tz:package` → `package/R2P2-TZ-combined.uf2`.

Phase 2 (**verified on hardware 2026-07-07**, board 1 Pico 2, via
`TZ.selftest` from irb — 39/39 checks: keystore/policy/handles, HKDF
export determinism, AEAD round-trip + tamper + no-write-on-mismatch,
verify_mrb signature/latch/rollback/tamper): the crypto veneers are
real — OTP-backed keystore with chip-ID dev fallback on blank pages
(`monitor/keystore.c`), HKDF/HMAC over the hardware SHA-256 and
ChaCha20-Poly1305 over the mbedTLS chacha20/poly1305 slice
(`monitor/sg_crypto.c`), and `sg_verify_mrb` (ECDSA P-256 via vendored
micro-ecc; envelope format `include/r2p2_mrb_envelope.h`; host signer
`tools/mrb_sign.rb`; OTP thermometer anti-rollback, write path gated
behind `R2P2_TZ_OTP_WRITE=1`; success unlocks `SG_SLOT_GATEWAY_PSK`).
RFC/host test vectors: `tools/sg_crypto_test.c` (build line in the file).

Also hardware-verified 2026-07-07: the **sealed-monitor path** (item 2
minus the burn) — `R2P2_TZ_SIGKEY=tz/tools/boot_signing_dev.pem rake
r2p2:tz:package` seals the patched monitor with picotool (`signature:
verified`), emits `package/bootkey_otp.json` (the BOOTKEY fingerprint
rows for the eventual, irreversible, board-1-only secure-boot enable),
and the sealed image boots. And the **NS Ruby surface** (`tz/ns/tz_api.c`):
`Digest::SHA256.digest/hexdigest` (hardware SHA-256 via `sg_sha256`;
one-shot by decision), `TZ.derive_key(info, len=32, slot=0)` feeding
`MbedTLS::Cipher#key=` (tier-2 session crypto — AES-256-GCM round-trip
verified in irb on target), and `TZ.verify_mrb`. The picoruby-mbedtls gem
is now in the pico2 build config; its entropy comes from `sg_random_bytes`
via the rand_ns wrap. Item 0 (probe-first diagnostics) landed 2026-07-07 and was verified on a
Pico 2 W + Debug Probe: the bring-up LED scaffolding is gone (LED path
survives behind `cmake -DR2P2_TZ_LED_DIAG=1`, the non-W board 1 default),
replaced by the `tz_diag` record at 0x20080000 — boot-stage stamps +
full fault dump, read over SWD (`tools/PROBE.md`, `tools/tz_diag.gdb`).
openocd (RPi fork) also replaces BOOTSEL for the dev loop: `program
<ns.elf>` + `program <monitor_packaged.elf> verify reset exit`.

Still open: the secure-boot OTP burn itself, real
key provisioning to OTP pages 48/49. This directory holds the shared
contract between the two firmware images of a Secure/Non-secure split
R2P2:

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
2. **Ship-together with a hash manifest** (revised 2026-07-02; originally
   "one signed unit via LOAD_MAP"). The bootrom verifies only the monitor's
   signature; the monitor authenticates the NS image by comparing its
   SHA-256 against a digest in the signed `.ns_manifest` section
   (`monitor/main.c` `verify_ns_image()`, ~30 lines on the already-linked
   `pico_sha256`). The digest is patched in at packaging time
   (`rake r2p2:tz:package`) and the monitor is sealed AFTER patching, so
   the boot signature transitively covers the NS bytes. Trade-off accepted:
   every NS change re-patches + re-signs the monitor — fine while both
   images ship together. If NS ever updates independently in the field,
   graduate to a signed manifest verified against a stable public key
   (ECDSA in the monitor); the manifest carries a `version` field from day
   one so that extends rather than replaces this format. (The bootrom
   cannot launch an `EXE_SECURITY=NS` image — `rp2350_arm_ns` is "not
   directly bootable", §5.9 — so the monitor performs the NS entry itself
   in every variant.) Still no mbedTLS in the monitor.
3. **`sg_verify_mrb` is deferred to phase 2** and returns
   `SG_ERR_NOT_PERMITTED` until the verification story (ECDSA vs HMAC seal)
   is settled. *(Settled 2026-07-07: ECDSA P-256 verify-only via vendored
   micro-ecc — nothing to provision on pristine OTP, private key stays on
   the host; HMAC seal documented as the fallback had it not fit. See
   `include/r2p2_mrb_envelope.h` and the implementation in
   `monitor/sg_veneers.c`.)*
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
- With phase-1 decisions (no mbedTLS md/bignum, ChaCha20-Poly1305 + HKDF
  over the hardware SHA-256), 8 KiB of data/stack RAM works. Measured
  phase-2 budget (map file + `-fstack-usage`): .data+.bss ≈ 2.6 KiB, libc
  heap 256 B, stack 4 KiB (`PICO_STACK_SIZE`), of which micro-ecc's
  P-256 verify chain transiently needs ~1 KiB — the mbedTLS-ECDSA route
  (~4-6 KiB stack) was avoided by vendoring micro-ecc. RAM vector table
  and the default alarm pool are compiled out (`PICO_NO_RAM_VECTOR_TABLE`,
  `PICO_TIME_DEFAULT_ALARM_POOL_DISABLED`). Re-measure on any crypto
  change; the linker does not warn about stack overflow into .bss. At
  *boot* the monitor may additionally use main RAM as scratch (key
  derivation) as long as it wipes it before configuring the SAU and
  jumping to NS.

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
  acceptable), `SYSINFO`, `TBMAN`, and **`RESETS`** (the block itself).
- **RESETS needs BOTH grants** (datasheet §10.6.2.2): peripheral drivers
  (`uart_init`, `i2c_init`, ...) reset their block on init via the RESETS
  register, which faults from NS unless the RESETS block is NS-granted.
  This is safe — each reset bit is independently gated by that
  peripheral's own ACCESSCTRL, so NS still cannot reset the Secure-only
  peripherals (OTP/XIP/CLOCKS/etc.). Confirmed on target: without the
  RESETS grant, `uart_init` BusFaulted at boot.
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
3. **Packaging** (`rake r2p2:tz:package`): SHA-256 the built NS `.bin` →
   `objcopy --update-section .ns_manifest` into the monitor ELF →
   `picotool seal --sig` (if `R2P2_TZ_SIGKEY` set; unsigned dev package
   otherwise) → regenerate the monitor UF2 → concatenate monitor+NS UF2s
   into `R2P2-TZ-combined.uf2` (UF2 blocks are self-addressing, one
   BOOTSEL drop flashes both).
4. **Partition table** (`monitor/r2p2_tz_pt.json`, embedded via
   `pico_embed_pt_in_binary` — "partition-table-in-image boot", §5.1.14).
   Two partitions: `firmware` (0–0x340000, `nonsecure:""` so NS cannot
   reflash the monitor/NS image; accepts both `rp2350-arm-s` and
   `rp2350-arm-ns` families so the combined UF2 drop routes both halves)
   and `fs` (0x340000–end, `nonsecure:"rw"` — what makes `flash_ns.c`'s NS
   writes accepted by `checked_flash_op`). The table rides in the monitor
   image, loaded as the resident table `checked_flash_op` validates
   against. **On-target TODO:** confirm the combined-UF2 family routing and
   `partition info` on real silicon (this dev picotool lacks the subcommand).
5. Boot: bootrom verifies the monitor image + enters it (S) → monitor
   SHA-256-verifies the NS region against `.ns_manifest` (dev builds with
   an unpatched manifest skip this) → derives keys from OTP + ratchets
   SW_LOCK → configures SAU + ACCESSCTRL(+LOCK) + ITNS + DMA SECCFG + GPIO
   NS masks, enables the bootrom NS APIs above → sets VTOR_NS/MSP_NS +
   NSACR → `blxns` into the NS reset handler. See `monitor/main.c`.

## Building (both images)

```sh
# 1. Secure monitor (standalone) — produces r2p2_sg_implib.o
cd mrbgems/picoruby-r2p2/tz/monitor
PICO_SDK_PATH=/path/to/pico-sdk cmake -B build -S . && cmake --build build

# 2. Non-secure R2P2 — links the implib from step 1
cd <picoruby root>
R2P2_TRUSTZONE=1 \
  PICO_SDK_PATH=/path/to/pico-sdk \
  PICO_EXTRAS_PATH=/path/to/pico-extras \
  rake r2p2:picoruby:pico2:prod
# artifacts in build/r2p2/picoruby/pico2/prod-tz/

# 3. Package: patch NS digest into the monitor, seal, combined UF2
rake r2p2:tz:package                      # unsigned dev package
R2P2_TZ_SIGKEY=key.pem rake r2p2:tz:package  # sealed for secure boot
# -> build/r2p2/picoruby/pico2/prod-tz/package/R2P2-TZ-combined.uf2
```

`R2P2_TRUSTZONE=1` defaults `R2P2_TZ_IMPLIB` to the monitor's standalone
build output; set it explicitly to point elsewhere. The rake task appends a
`-tz` suffix to the build dir so TZ and stock artifacts coexist. pico2 only.
An unpackaged monitor (placeholder manifest) skips the NS hash check at
boot, so plain dev iteration doesn't require repackaging on every change.

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
| `picoruby-machine` | **modify** | `Machine.set_hwclock`/time-of-day used `pico_aon_timer` (POWMAN, Secure-only) and faulted at boot; now backed by a TIMER0 software clock via `ns/aon_ns.c` (`--wrap` of the 4 `aon_timer_*` fns). Does not persist across deep sleep — a real AON clock needs an `sg_aon_*` veneer later. `Machine.deep_sleep`/`sleep` still touch XOSC/ROSC/CLOCKS/POWMAN → will fault if called from Ruby; `sg_deep_sleep()` veneer (phase 2) or disable. Unique-id via bootrom `get_sys_info` (NS API) works. `Machine.read_memory` of Secure addresses now SecureFaults (hardware-enforced). |
| `pico_bootsel_via_double_reset` | **dropped (TZ build)** | its `__attribute__((constructor))` reads `powman_hw->chip_reset` (POWMAN, Secure-only) before `main` → BusFault. Unlinked in the TZ build (main CMakeLists); BOOTSEL still reachable via the button / OTP `DOUBLE_TAP`. |
| `picoruby-rng` | unchanged | keeps calling `get_rand_32()`; the NS image redirects `get_rand_*` to `sg_random_bytes()` via linker `--wrap` (`ns/rand_ns.c` — the TRNG is Secure-only and would fault from NS) |
| `picoruby-filesystem-fat` | unchanged | keeps calling `flash_range_program/erase`; the NS image `--wrap`s them (`ns/flash_ns.c` → bootrom `checked_flash_op`, partition-checked against NS_W, + `sg_flash_flush_cache()` since the ROM op does no cache maintenance and the ROM flush is Arm-S-only). NB: this gem's ports are excluded from the non-WiFi build anyway (littlefs is used) — the wrap covers whichever HAL is compiled. |
| `picoruby-littlefs` | unchanged | same coverage via `ns/flash_ns.c` |
| `picoruby-mbedtls` | unchanged | `mbedtls_hardware_poll` → `get_rand_64` is covered by the `get_rand_*` `--wrap`; raw-key `Cipher` API unchanged by design |
| `picoruby-psg` | compiles; runtime-limited | its Ruby-binding `src/psg.c` is compiled into `libmruby.a` and references the port symbols, so the ports **cannot** be dropped at the R2P2-CMake level without a link error. Left compiled; its core-1 launch will fault at runtime until `sg_launch_core1_ns()` exists (phase 2). Truly excluding it needs a TZ-specific mruby build_config that drops the gem from the VM. |
| `picoruby-pitchdetector` | compiles; runtime-limited | same coupling as psg |
| `picoruby-cyw43` / `-net` / `-socket` / `-ble` (pico2_w) | **defer/audit** | driver itself uses PIO/DMA/GPIO (all NS-granted incl. NSMASK bits); the lwIP/mbedTLS `pico_rand`→TRNG hazard is covered by the `ns/rand_ns.c` override. Remaining: general audit. Phase 1 targets plain pico2. |
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
