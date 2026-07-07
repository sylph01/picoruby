# Phase 2 backlog — TrustZone R2P2

Written 2026-07-07. Phase 2 is functionally complete and hardware-verified
(crypto veneers, `sg_verify_mrb`, the NS Ruby surface, probe diagnostics,
and secure boot — all on board 1). What remains is genuine backlog: not
phase-2-critical, recorded so it isn't lost. The intended order is to do
**WiFi under TZ first** (`WIFI-UNDER-TZ-HANDOFF.md`), then pick from here.

Items are roughly independent unless a dependency is noted. Each lists
*what*, *why*, *where*, and rough *effort*.

## 1. `sg_launch_core1_ns()` — core-1 NS launch (+ veneer reentrancy)

- **What:** a veneer that launches core 1 into Non-secure state. The
  bootrom's core-1 launch protocol runs Secure-side, so NS cannot start
  core 1 itself. The monitor pins core 1 Non-secure
  (`ACCESSCTRL FORCE_CORE_NS.CORE1`) and releases it into a given NS entry.
- **Why:** picoruby-psg / pitchdetector launch core 1 at runtime; under TZ
  that faults today. Also any future move of cyw43 to core 1 for
  throughput.
- **Coupled work — veneer reentrancy guards:** the moment two cores can
  call veneers, every veneer needs a busy flag / spinlock at entry. There
  is a TODO at the top of `sg_veneers.c`. The current design explicitly
  assumes a single NS caller (core 0, thread mode, cooperative scheduler);
  `sg_launch_core1_ns` breaks that assumption, so the guards are a
  prerequisite of shipping it, not an afterthought.
- **Where:** ABI slot is already reserved (commented signature in
  `include/r2p2_sg_api.h`). Monitor side + `partition_configure`.
- **Effort:** medium (the veneer is small; the reentrancy audit across all
  veneers is the real cost).

## 2. TZ-specific mruby build_config to drop psg/pitchdetector

- **What:** a build config that genuinely removes psg/pitchdetector from
  the VM. Their `src/*.c` in `libmruby.a` reference the port symbols
  (`psg_drv_*`, `PSG_tick_start_core1`), so they can't be cut at the
  R2P2-CMake level (`cmake/CMakeLists.txt` has a NOTE about this).
- **Why:** until item 1 exists, these gems fault at runtime under TZ (core
  1 launch). Dropping them from the VM is the cheaper interim fix and
  reduces the NS image.
- **Where:** a new `build_config/` variant; the gembox/gem list.
- **Effort:** low–medium. Consider doing this *before* item 1 as the quick
  unblock, and item 1 later as the real fix.

## 3. `sg_deep_sleep()` + `sg_aon_*`

- **What:** a fixed-menu veneer for `Machine.deep_sleep`/`sleep`. CLOCKS,
  ROSC, and POWMAN are Secure-only, so NS deep-sleep accesses fault. The
  veneer offers a closed set of sleep states rather than raw register
  access.
- **Related:** the software AON clock (`ns/aon_ns.c`, TIMER0-backed) does
  not survive deep sleep; a real wall clock across sleep needs an
  `sg_aon_*` veneer over the Secure AON timer/POWMAN.
- **Why:** power management is currently unavailable under TZ.
- **Where:** new veneers in `sg_veneers.c` + header slots; `ns/aon_ns.c`.
- **Effort:** medium (POWMAN state machine is fiddly; keep the menu small).

## 4. Secure-stack sealing

- **What:** store the Arm sentinel `0xfef5eda5` at the Secure stack limits
  (TrustZone-M stack-sealing recommendation) in the monitor startup.
- **Why:** defense-in-depth against a return-into-unsealed-stack on the
  Secure side. Currently a TODO in `ns_launch` / crt0.
- **Where:** monitor crt0 / startup, `memmap_monitor_s.ld` stack symbols.
- **Effort:** low.

## 5. Separate signed application image (design option)

- **What:** let application code be its own signed image/partition that the
  monitor verifies before launch — analogous to how it already verifies
  the NS image via `.ns_manifest` — instead of recompiling the whole NS
  firmware for every app change.
- **Why:** today, giving app code secure-boot integrity means baking it
  into the NS binary (see the README "Application code integrity" section).
  A separate signed image gives the same boot-time guarantee while
  re-signing only the app. RP2350 partition tables support multiple signed
  partitions.
- **Where:** a second manifest + verify step in the monitor; packaging in
  `tasks/picoruby/r2p2.rake`; partition table `r2p2_tz_pt.json`.
- **Effort:** medium–high. Only worth it if the rebuild-the-monolith cost
  becomes painful.

## 6. Production key provisioning / real GATEWAY_PSK

- **What:** a real deployment board provisioned with a per-device random
  DEVICE_ROOT and the real server-shared GATEWAY_PSK (board 1's is a random
  placeholder, now permanent), plus the full lockdown.
- **Why:** board 1 is a debug board with a placeholder PSK and debug left
  enabled; it can't be a production secure device.
- **Where:** the "Hardened production board" recipe in `tools/OTP-BURN.md`
  is complete and ready — this is an execution task on a fresh board, not
  new code.
- **Effort:** low (follow the recipe), but irreversible — treat with the
  same gates used in Part V of the burn log.

## 7. Veneer address stability across independent NS updates

- **What:** pass the previous implib via `--in-implib` on monitor rebuilds
  so veneer addresses stay fixed, if the NS image is ever updated against
  an already-flashed monitor.
- **Why:** currently moot (monitor + NS always reflash together). Becomes
  relevant with item 5 (independent app image) or field NS updates.
- **Where:** `monitor/CMakeLists.txt` (the `--in-implib` line is already
  present but commented).
- **Effort:** low, but only matters once updates decouple.

## 8. Production debug lock in the monitor

- **What:** the monitor leaves `ACCESSCTRL.LOCK` debug bits clear during
  bring-up (comment in `partition_configure`). A production monitor build
  should set `ACCESSCTRL_LOCK_DEBUG_BITS`, coordinated with the OTP
  `CRIT1` debug-disable (production hardening).
- **Why:** defense-in-depth; ties into item 6.
- **Where:** `partition_configure` in `tz/monitor/main.c`.
- **Effort:** low.

## 9. Cosmetic: R2P2 logo under TZ

- The R2P2 boot logo renders slightly off under the TZ build. Cosmetic;
  low priority.

## Explicitly NOT doing (closed decisions, recorded so they aren't reopened)

- **Streaming `Digest::SHA256`** — one-shot only by decision: the hardware
  SHA engine holds state under an exclusive bootrom lock, so a streaming NS
  API would let NS pin a Secure resource across calls. `digest`/`hexdigest`
  only.
- **HMAC seal for `sg_verify_mrb`** — settled as ECDSA P-256 (verify-only,
  vendored micro-ecc). HMAC would be symmetric (no third-party
  authorship, can't verify on a blank chip). Documented in the README
  phase-1-decisions note.
- **Full mbedTLS in the monitor** — the monitor uses only the ChaCha20 +
  Poly1305 primitive slice; no md/bignum/ECP. The 8 KiB RAM budget and the
  minimal-TCB principle stand.
