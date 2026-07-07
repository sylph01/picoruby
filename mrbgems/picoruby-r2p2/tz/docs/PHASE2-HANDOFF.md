# R2P2 TrustZone — Phase 2 hand-off

Written 2026-07-04, at the close of phase 1. This document is the entry
point for resuming the project **in the picoruby repository** (all the code
already lives here; earlier work sessions merely ran from a pico-sdk
checkout). Read `../README.md` first for the design; this document is only
about *what to do next* and *what to watch out for*.

## Where things stand

- Branch: `trustzone-sketch` (43 commits on top of master).
- Status: **phase 1 verified on hardware 2026-07-03** (Pico 2, SDK 2.2.0,
  arm-none-eabi-gcc 14.2). Monitor boots, SHA-256-verifies the NS image,
  partitions the chip (SAU/ACCESSCTRL/ITNS/DMA/GPIO masks), `blxns`es into
  a Non-secure mruby VM running the full R2P2 shell over USB CDC.
- Field-verified veneer round-trips: `sg_random_bytes` (via the RNG gem),
  `sg_flash_erase`/`sg_flash_program`/`sg_flash_flush_cache` (FAT format at
  boot **and** runtime `File.open(path,"w")` write + read-back), `sg_sha256`
  (the monitor's own NS-image verify).
- A companion document, `PHASE1-COMMIT-WALKTHROUGH.md`, explains every
  phase-1 commit for maintainers.

### Build & flash (unchanged from README)

```sh
# 1. Secure monitor (standalone; produces r2p2_sg_implib.o)
cd mrbgems/picoruby-r2p2/tz/monitor
PICO_SDK_PATH=... cmake -B build -S . && cmake --build build

# 2. Non-secure R2P2 (links the implib)
R2P2_TRUSTZONE=1 PICO_SDK_PATH=... PICO_EXTRAS_PATH=... \
  rake r2p2:picoruby:pico2:prod

# 3. Package (patch NS digest into monitor, combined UF2)
rake r2p2:tz:package
# -> build/r2p2/picoruby/pico2/prod-tz/package/R2P2-TZ-combined.uf2
```

**Workflow gotcha:** the R2P2 build embeds the git SHA in artifact paths.
Commit first, then build, or you will pick up stale artifacts — and use
`ls -t | head -1` when hunting for the newest build output.

### Hardware notes

- **Board 1 = pristine OTP. Use it for TrustZone / secure-boot work.**
- Board 2 is a contest board with a burned BOOTKEY — do NOT use it for
  secure-boot experiments.
- A Raspberry Pi Debug Probe (SWD + UART) has been ordered. Once it
  arrives, prefer it over the LED-blink debugging channel, and do the
  scaffolding strip-down (below).
- `tio` is the serial client in use (`tio -m INLCRNL /dev/ttyACM0`).

## Phase-2 work items

In rough dependency order. Items 1–3 are the phase-2 core; item 0 is a
small prerequisite cleanup.

### 0. Strip the bring-up scaffolding (once the Debug Probe arrives)

All of it is silent unless something fails, so there is no urgency, but it
should not ship:

- `ns/ns_trap.c` + its five `--wrap` lines in `ns/ns_build.cmake`
  (abort/exit/panic/`__assert_func`/`hard_assertion_failure` → LED blink).
- `ns/exit_ns.c`'s exception-index LED blink (the `_exit` override itself
  may stay if a sane halt behavior is wanted; the LED loop goes).
- The `mrb_protect_error` blink readout around `mrb_task_run` in
  `ports/rp2040/main.c` (the protection itself is arguably worth keeping —
  decide; only the LED part must go).
- The monitor's per-stage LED breadcrumbs in `monitor/main.c` (marked
  TEMPORARY) and the fault-handler PC blink-out — consider keeping the
  fault handlers but routing the report to the probe/UART instead.

### 1. Real crypto veneers (keystore, HKDF, ChaCha20-Poly1305, HMAC)

The stubs exist and return `SG_ERR_NOT_PERMITTED`; the ABI (handles,
policy bits, request structs) is already frozen in
`include/r2p2_sg_api.h`. What's needed:

- **Key material source:** `monitor/main.c` has a key-derivation stub that
  reads OTP and ratchets `SW_LOCK` — replace the stub derivation with the
  real one (OTP page/row assignment TBD). The slot→OTP-row mapping and
  per-slot policy table must live **in the monitor image only** (README
  "Known open items") so an NS rebuild can't repoint or repolicy a slot.
- **Cipher code:** phase-1 decision 4 says ChaCha20-Poly1305 + HKDF over
  the hardware SHA-256, *no full mbedTLS in the monitor*. The staged plan
  (comment block in `monitor/CMakeLists.txt`) is to compile just the
  mbedtls symmetric slice — `chacha20.c`, `poly1305.c`, `chachapoly.c`,
  `hkdf.c` from `${PICO_SDK_PATH}/lib/mbedtls/library` with a minimal
  config — or hand-rolled equivalents if even that doesn't fit.
- **Memory budget is the hard constraint:** the monitor has 8 KiB total
  RAM (SRAM8+9) of which the stack is 2 KiB and the libc heap 2 KiB
  (both shrinkable via `PICO_STACK_SIZE`/`PICO_HEAP_SIZE`). A tuned
  mbedTLS wants 4–6 KiB of stack. Measure before and after; the linker
  will not warn about stack overflow into .bss. If it doesn't fit,
  options: shrink the heap (the monitor barely allocates), use a static
  workspace instead of stack buffers, or drop to standalone RFC 8439
  reference code (~2 KiB code, small stack).
- **ABI rules already decided — implement them exactly:**
  - `cmse_nonsecure_entry` functions cannot take stack-passed args, hence
    the `sg_aead_op_t` / `sg_derive_export_t` request structs.
  - **TOCTOU rule:** `memcpy` the request struct into Secure stack FIRST,
    then `rom_validate_ns_buffer()` the copied pointer fields, and never
    re-read the NS struct afterwards (NS can rewrite fields mid-call).
    This is written as a TODO on `sg_key_derive_export` in
    `monitor/sg_veneers.c`.
  - Every NS pointer goes through `ns_buffer_ok()` (the
    `rom_validate_ns_buffer` wrapper already in `sg_veneers.c`).
  - `sg_aead_decrypt` must write **nothing** on tag mismatch
    (`SG_ERR_AUTH_FAILED`) — don't decrypt-then-check into the NS buffer.
- **Reentrancy:** veneers currently assume a single NS caller (core 0
  thread mode; R2P2's cooperative scheduler guarantees it). The moment
  `sg_launch_core1_ns` exists, every veneer needs a busy flag/spinlock at
  entry — there's a TODO at the top of `sg_veneers.c`.
- **Ruby surface (separate, later):** the intended consumer path is
  `sg_key_derive_export` feeding `MbedTLS::Cipher#key=` for NS-side
  session crypto (tier-2 model: NS compromise reveals a session key,
  never a parent key). Also deferred by explicit decision: a
  `Digest::SHA256` gem backed by `sg_sha256` (name chosen 2026-07-03;
  CRuby-style one-shot `digest`/`hexdigest` first — the veneer is
  deliberately one-shot, see the `sg_sha256` comment in the header).

### 2. Combined-image signing / secure boot

The packaging pipeline is already signing-shaped; what's missing is doing
it for real and burning OTP.

- Pipeline today (`rake r2p2:tz:package`): SHA-256 of NS `.bin` →
  `objcopy --update-section .ns_manifest` into the monitor ELF →
  **if `R2P2_TZ_SIGKEY` is set** `picotool seal --sig` (after patching, so
  the signature covers the digest) → regenerate UF2 → concatenate into the
  combined UF2. Test the signed path first *without* touching OTP —
  a sealed image boots fine on a non-secure-boot board.
- OTP procedure (datasheet §10.5, summarized in README "Secure boot
  enable"): program a public-key fingerprint at `BOOTKEY0_0`, set
  `BOOT_FLAGS1.KEY_VALID` (+ `KEY_INVALID` for unused slots), disable
  debug via `CRIT1.DEBUG_DISABLE` (or a debug key), optionally glitch
  detectors, disable unused boot paths in `BOOT_FLAGS0`, then
  `CRIT1.SECURE_BOOT_ENABLE`. **Irreversible. Board 1 only, and only when
  the signed image is proven to boot.** Practice the picotool
  key-generation + seal flow and verify the sealed UF2 boots repeatedly
  before any OTP write.
- On-target TODO carried over from phase 1: confirm combined-UF2 family
  routing against the embedded partition table with
  `picotool partition info` (the picotool used during phase 1 lacked the
  subcommand — build/fetch a newer one).
- Dev-loop preservation: an *unpackaged* monitor (placeholder manifest,
  magic=0) deliberately skips the NS hash check so plain cmake builds stay
  bootable. Keep that property; it's what makes iteration bearable. Once
  secure boot is burned, every flash needs the full package step — that's
  expected and fine on board 1 only.

### 3. `sg_verify_mrb` (signed bytecode)

Reserved in the ABI (returns `SG_ERR_NOT_PERMITTED`); design decisions
still open — settle these first:

- **ECDSA signature vs HMAC seal.** HMAC (key from the OTP-derived tree)
  is tiny and fits the no-mbedTLS budget but means "sealed by this device
  /fleet key", not third-party-verifiable authorship. ECDSA P-256 verify
  gives real signatures but reopens the memory-budget question (a
  verify-only P-256 is ~a few KiB code + ~2 KiB stack — borderline; see
  item 1's budget notes). The slot for it (`SG_SLOT_MRB_VERIFY`,
  verify-only policy) exists either way.
- **Envelope format** (TBD): needs at minimum magic/version, payload
  length, rollback counter, signature/tag over all of it.
- **Rollback protection:** monotonic counter in OTP thermometer rows,
  monitor-side check (already sketched in the header comment).
- **Honest scope** (keep this in the doc/comments — it was an explicit
  decision): this attests buffer contents *at call time*. NS owns the
  buffer and the VM; it is a policy gate (e.g. "only verified packages may
  open `SG_SLOT_GATEWAY_PSK`"), not an NS-integrity guarantee. The
  boundary protects keys, not NS control flow.

### 4. Backlog (not phase-2-critical, recorded so they don't get lost)

- `sg_launch_core1_ns()` — bootrom core-1 launch is Secure-side; needed
  before picoruby-psg / pitchdetector work under TZ (their core-1 launch
  faults at runtime today). Pin core 1 NS via `ACCESSCTRL_FORCE_CORE_NS`.
  Then add the veneer reentrancy guards (item 1).
- `sg_deep_sleep()` — `Machine.deep_sleep`/`sleep`'s CLOCKS/ROSC/POWMAN
  accesses fault from NS; needs a fixed-menu veneer. Related: the software
  AON clock (`ns/aon_ns.c`) doesn't survive deep sleep; a real wall clock
  needs an `sg_aon_*` veneer.
- Secure-stack sealing (`0xfef5eda5` at stack limits, Arm TrustZone-M
  recommendation) in the monitor startup.
- A TZ-specific mruby build_config to genuinely drop psg/pitchdetector
  from the VM (their `src/*.c` in libmruby.a pins the port symbols, so
  they can't be cut at the R2P2-CMake level).
- Veneer address stability: on monitor rebuilds pass the previous implib
  via `--in-implib` if you ever need to update NS against an
  already-flashed monitor (moot while both reflash together).
- Cosmetic: the R2P2 logo renders slightly off under the TZ build.

## Hard-won facts — do not relearn these on hardware

1. **NS cannot perform flash ops, full stop.** The bootrom's raw `'FO'`
   `checked_flash_op` leaves flash/XIP unreadable across the call and does
   not re-enter XIP for the caller → the NS caller's next instruction
   fetch from flash hangs the core (confirmed on target). The SDK's
   `flash_safe_execute` can't be used from NS either — it takes the
   BOOTRAM lock, and BOOTRAM (0x400e0000) is hardwired Secure-only. Hence
   `sg_flash_erase/program` run Secure-side using the SDK's RAM-resident
   `flash_range_*`, IRQ-masked, clamped to `[TZ_FS_OFFSET,
   TZ_FS_OFFSET+TZ_FS_SIZE)`. If you ever touch this code, re-verify that
   `flash_range_*` still land in RAM (their section is copied by crt0's
   data-copy table; check the map file for a 0x2008xxxx VMA).
2. If anything ever calls `checked_flash_op` again: the flags word's
   SECLEVEL field (bits 9:8) **must be nonzero** (1=SECURE, 2=NONSECURE,
   3=BOOTLOADER); 0 is rejected with `BOOTROM_ERROR_INVALID_ARG` (-5).
3. **`tud_task()` is not reentrant.** Under TZ, USB is serviced from
   exactly one place: `usb_irq_handler` (USBCTRL_IRQ 14, routed NS via
   ITNS). `picorb_hal_getchar`'s own `tud_task()` call is compiled out
   under `R2P2_TRUSTZONE`; do not add tud_task calls anywhere else, and if
   a halt-state loop must service USB itself, it must
   `irq_set_enabled(USBCTRL_IRQ, false)` first.
4. BOOTRAM (bootrom locks, boot locks), CLOCKS, POWMAN, RESETS-of-secure-
   peripherals, TRNG, SHA256, OTP, XIP_CTRL/QMI are all Secure-only. The
   NS runtime-init trimming (`ns/runtime_init_ns.c` + skip defines in
   `ns/ns_build.cmake`) and `ns/aon_ns.c` exist precisely because stock
   SDK/gem code touches these before `main`. Any new gem or SDK feature
   enabled in the NS build should be audited for pre-main constructors and
   Secure-peripheral access (that's how `pico_bootsel_via_double_reset`
   had to be unlinked).
5. `--wrap` is the override mechanism for SDK INTERFACE-library symbols
   (their .c files are peer objects of the executable, so redefinition
   collides). Caveat: `--wrap` cannot redirect a call that was **inlined
   within the same translation unit** (bit us with `mrb_print_error`
   inside mruby's `exc_throw`).
6. ACCESSCTRL writes need the `0xacce` password in the upper 16 bits;
   memory devices reset NS-open (SRAM8/9 must be *revoked*), peripherals
   reset Secure-only (must be *granted*). RESETS needs the block-level
   grant **and** the per-peripheral grant (datasheet §10.6.2.2).
7. Veneer functions need `__attribute__((cmse_nonsecure_entry, noipa,
   used))` — GCC IPA otherwise clones stubs into `*.constprop` locals,
   which CMSE veneer generation rejects (already encoded in `SG_API`).

## Session-memory migration

Phase-1 sessions ran from a pico-sdk checkout, so the assistant's
persistent memory for this project lives under that project's memory dir
(`~/.claude/projects/-home-sylph01-projects-pico-sdk/memory/`,
`r2p2-trustzone-status.md`). Everything durable from it has been folded
into this document and the walkthrough; when starting sessions from
`~/projects/picoruby`, seed the new project memory from here (or just
point the assistant at this file).
