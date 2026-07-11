# Phase 2 backlog — TrustZone R2P2

Written 2026-07-07. Phase 2 is functionally complete and hardware-verified
(crypto veneers, `sg_verify_mrb`, the NS Ruby surface, probe diagnostics,
and secure boot — all on board 1). What remains is genuine backlog: not
phase-2-critical, recorded so it isn't lost. The intended order is to do
**WiFi under TZ first** (`WIFI-UNDER-TZ-HANDOFF.md`), then pick from here.

Items are roughly independent unless a dependency is noted. Each lists
*what*, *why*, *where*, and rough *effort*.

## 1. `sg_launch_core1_ns()` — core-1 NS launch (+ veneer reentrancy)

**DONE + device-verified (2026-07-11, probe pico2 board). Full
launch/park/relaunch cycle PASSES** (`TZ.selftest` RESULT: PASSED, twice in
one boot): launch → NS entry runs on core 1 → deep-sleep gated
`NOT_PERMITTED` while core 1 is up → park → relaunch → runs again → park.

**Design that shipped (Secure trampoline; FORCE_CORE_NS dropped):**
`FORCE_CORE_NS.CORE1` was architecturally broken with the bootrom launch
(a forced-NS core bus-errors on the Secure ROM/SIO handshake; and a plain
bootrom `blx` into an NS address is an illegal S→NS transition). Instead,
core 1 is launched through the ordinary Secure bootrom mailbox into a
monitor-resident Secure trampoline (`core1_ns_trampoline`, main.c) which
configures core 1's **banked** SAU + NSACR/CPACR identically to core 0's
(shared helpers `tz_sau_configure_ns_regions` / `tz_grant_ns_coprocessors`),
sets NS VTOR/MSP_NS, and BXNSes into the caller's entry. Veneer
(`sg_veneers.c`) validates NS-range/alignment and delegates via
`tz_core1.h`. Every launch starts with a PSM `FRCE_OFF` PROC1 pulse, so
park/relaunch and payload replacement all go through one path.

**RCP salt lessons (expensive to learn, do not repeat):**
- Core 1's RCP salt is seeded once by the bootrom at cold boot (core 0
  writes both cores' salts, `varm_boot_path.c` step 4) and **survives PSM
  FRCE_OFF PROC1 pulses** — the SDK's `multicore_reset_core1`/relaunch has
  no RCP handling at all and relies on exactly that. Relaunch after PSM
  reset therefore needs no seeding.
- Runtime re-seeding from core 0 (`mcrr p7,#8,…,c1`) is FATAL when the salt
  is already valid: core 0 stalls forever mid-`mcrr`, un-haltable even over
  SWD (memory reads via the bus AP still work — that's how the breadcrumb
  was recovered). Never write the salt outside the bootrom cold path.
- The "core 1 stuck at `wait_for_rcp_salt`" state that motivated seeding is
  a **debug-probe artifact**: openocd's per-core resets clear core 1's RCP
  while core 0's stays valid, so the bootrom's seed-skip (`bmi` on
  canarystatus) leaves core 1 salt-less. In that state the launch fails
  bounded (`SG_ERR_INTERNAL`, core 0 and the VM stay alive). Recovery: any
  full-chip reset — physical POR or watchdog trigger
  (`mww 0x40018008 0x01fffff3; mww 0x400da000 0x80000000` over SWD, NOT
  openocd `reset`). After openocd `program … reset exit` the artifact state
  is present; always watchdog-reboot before exercising the launch.

ABI: SG_API_VERSION 0x0003 (`sg_launch_core1_ns`, `sg_deep_sleep`,
`sg_aon_*`). Reentrancy try-lock guards (`SG_ERR_BUSY`) shipped earlier and
re-verified through the full selftest.

- **What:** a veneer that launches core 1 into Non-secure state. The
  bootrom's core-1 launch protocol runs Secure-side, so NS cannot start
  core 1 itself. The monitor launches core 1 into a Secure trampoline that
  mirrors core 0's S→NS crossing (banked SAU + coprocessor grants, then
  BXNS) — no bus-level FORCE_CORE_NS.
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

**DONE — fully device-verified after two device-found bugs (2026-07-11,
board 2 + probe).** Final state: `Machine.sleep N` naps for exactly N
seconds (repeatable), USB detaches cleanly and re-enumerates ~1 s after
wake, the SAME irb session survives, the wall clock counts through the
nap, host/hub healthy, full selftest green (except item 1's known
core-1 checks). Getting there took three device iterations:

1. *USB hub kill.* The veneer stopped `clk_usb` with the pull-up
   attached mid-transaction; the frozen device took down the ENTIRE hub
   (all sibling devices; this rig's Bus 003 is internal → host reboot).
   Fix: `sleep_ns.c` detaches first — flush, quiesce USBCTRL_IRQ (the
   only tud_task caller under TZ), `tud_disconnect()`, nap,
   `tud_connect()` + IRQ back after.
2. *pico-extras `rosc_enable` idiom.* Writing the bare ENABLE field
   mask zeroes FREQ_RANGE → ROSC stops dead → wake path spins forever
   at 32 kHz (SWD PC-sample: parked in the stable-wait after a
   successful alarm wake).
3. *`clocks_init()`'s clk_ref-via-ROSC step.* Its glitchless switch
   onto a not-actually-running ROSC stalls clk_ref/clk_sys outright —
   the core stops mid-instruction, SWD dies entirely, and no software
   timeout can ever fire. LED breadcrumbs + SWD-examinability decoded
   this in one run.

Redesigned recipe (sg_veneers.c): no ROSC involvement at all, no WFI —
clock tree to LPOSC, PLLs/XOSC off, poll the POWMAN alarm flag at
32 kHz (pico-extras' core also spins; equivalent power), then rebuild
the boot clock tree strictly via verified sources (XOSC only after its
STABLE, PLLs after lock). Design rule earned on device: **never point a
glitchless mux at an unverified source — that failure mode is beyond
any software bound.** LED breadcrumbs kept (nap = LED dark on the
non-W pico2). Fixed menu:
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
