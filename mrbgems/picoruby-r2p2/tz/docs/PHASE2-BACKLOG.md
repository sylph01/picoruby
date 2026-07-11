# Phase 2 backlog — TrustZone R2P2

Written 2026-07-07. Phase 2 is functionally complete and hardware-verified
(crypto veneers, `sg_verify_mrb`, the NS Ruby surface, probe diagnostics,
and secure boot — all on board 1). What remains is genuine backlog: not
phase-2-critical, recorded so it isn't lost. The intended order is to do
**WiFi under TZ first** (`WIFI-UNDER-TZ-HANDOFF.md`), then pick from here.

Items are roughly independent unless a dependency is noted. Each lists
*what*, *why*, *where*, and rough *effort*.

## 1. `sg_launch_core1_ns()` — core-1 NS launch (+ veneer reentrancy)

**Reentrancy guard DONE + device-verified; core-1 LAUNCH FAILS ON DEVICE
(2026-07-11), needs a design fix.** What passed on the new pico2 board
(unsealed, image 4ff86745): the try-lock reentrancy guard (`SG_ERR_BUSY`,
`sg_version` exempt, bodies renamed `*_locked`) — every other veneer in
`TZ.selftest` still passes 39/39 through it — and the launch **parameter
rejection** (secure-vtor and odd-sp both correctly `BAD_PARAM`). The
monitor's bounded waits also proved out: a non-responding core 1 returns
`SG_ERR_INTERNAL` and core 0 / the VM stay fully alive (no Secure hang).

What FAILS: the actual launch/park/relaunch (6 checks). `sg_launch_core1_ns`
does not return `SG_OK`; core 1 never runs the NS entry. Root cause
(high confidence, from the RP2350 bootrom source `arm8_bootrom_rt0.S`):
the current design pins `FORCE_CORE_NS.CORE1` in `partition_configure`
and then hands `ns_entry` straight to the bootrom mailbox — but
  (a) the bootrom's core-1 wait/handshake loop executes from the **Secure**
      bootrom and mailboxes via the **Secure** SIO alias (`SIO_BASE`
      0xd0000000). A forced-NS core doing an NS-attributed access to the
      Secure SIO alias (or NS instruction fetch from Secure ROM) bus-errors
      → core 1 locks up before it can echo the handshake → our pop times
      out → `SG_ERR_INTERNAL`; and
  (b) even without the force bit, the bootrom finishes with `blx r6` to the
      supplied PC. A plain BLX from Secure state to an NS address (ns_entry
      is in the SAU-NS region) is an illegal transition (needs BLXNS), so a
      direct-to-NS launch can't work this way regardless.
**Fix direction:** launch core 1 through the normal Secure bootrom
handshake into a monitor-resident **Secure trampoline** (not directly to
ns_entry); the trampoline sets NS VTOR/MSP_NS and does the S→NS
`cmse_nonsecure_call`/BXNS into ns_entry itself — exactly how core 0's
`ns_launch` (main.c) already crosses into NS. Re-decide whether
FORCE_CORE_NS belongs at all (it breaks the pre-launch bootrom handshake
if set early; it could be applied by the trampoline just before BXNS, or
dropped in favor of the architectural S→NS transition). This is a design
change on a security boundary — deferred for a deliberate redo, not a
quick patch. ABI already bumped to 0x0002 (`SG_ERR_BUSY`); keep it.

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

**DONE (2026-07-11, commit 9ca065ea).** psg dropped in both halves
(`-tz` build configs for pico2 and pico2_w + port-source removal in the
R2P2 CMake — the port constructor claims a SIO spinlock pre-main, so
config-only removal wasn't enough). pitchdetector turned out to need
nothing: no build config includes it, its port objects are gc'd, and it
uses no core 1. Re-adding psg under TZ needs its port moved to
`sg_launch_core1_ns` (item 1) plus a designated-NS-core audit of the
core-1 loop.

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

**DONE + partially device-verified (2026-07-11).** On the new pico2
board, `TZ.selftest` passes the AON checks — clock live, monotonic
advance under a busy wait, NULL/menu-arg rejection — and `sg_deep_sleep`
argument validation. The dormant nap itself (`Machine.sleep`) is still
the manual irb test (drops USB, re-enumerates); not yet exercised on
this board. Fixed menu:
`sg_deep_sleep(SG_SLEEP_DORMANT_FOR_SECS, secs)` runs the pico-extras
dormant recipe Secure-side (LPOSC + PLL/XOSC off + POWMAN alarm wake;
PRIMASK_S held across the teardown; no vreg dialing yet); refuses while
core 1 is launched. `sg_aon_get_ms/set_ms` expose the Secure POWMAN
timer, started at boot by the monitor — wall clock persists across deep
sleep AND watchdog reboots. NS side: `aon_ns.c` rewired from the TIMER0
software clock to the veneers; new `sleep_ns.c` wraps `Machine_sleep`
(falls back to plain timed sleep on refusal). ABI 0x0003.
`TZ.selftest` covers AON liveness/advance + menu rejection; dormant
itself is a manual irb test (`Machine.sleep 3` — USB re-enumerates,
check `Machine.get_hwclock` advanced across the nap).

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

## Prioritization (2026-07-10, user decision)

High priority, in order: **item 2** (drop psg/pitchdetector from the TZ
VM), **item 1** (`sg_launch_core1_ns` + veneer reentrancy), **item 3**
(`sg_deep_sleep` + `sg_aon_*`), **item 6** (production provisioning).

Deferred:
- Items 4 and 8 (stack sealing, debug lock): user is confident in the
  mechanics from RP2350 Hacking Contest sample work; low risk, do near
  production hardening.
- Item 9 (logo): cosmetic; after the branch is mergeable.
- Items 5 and 7 (separate signed app image, implib stability): blocked
  on a rethink of the security model first.
