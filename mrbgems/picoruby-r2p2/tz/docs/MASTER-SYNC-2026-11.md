# Sync with master, 2026-11

`trustzone-sketch-4` = `trustzone-sketch-3` + a merge of master at `93f7ba7d`
(643 commits, four months) + the follow-ups below. This note records what
master changed underneath the TrustZone split, what the TZ side had to
change in response, and what has been re-verified since. The older docs in
this directory describe the pre-sync tree; where they disagree with this
note, this note wins.

## What master now provides (and the branch no longer carries)

- **Scheduler servicing.** The branch's `mrb_hal_task_switch_hook` (the
  first shape of mruby #6942) is gone. mruby merged
  `mrb_task_set_scheduler_hook`; picoruby-machine wraps it in
  `picorb_scheduler_service_add` and `ports/rp2040/machine.c` registers a
  service that calls `cyw43_arch_poll()` at every scheduler entry. That is
  the busy-VM starvation fix from `WIFI-UNDER-TZ-HANDOFF.md`, upstream.
- **cyw43 poll mode** is mainline for every WiFi build, including the idle
  hook (`cyw43_arch_wait_for_work_until`). The TZ build only differs by not
  linking btstack and not compiling the BLE port.
- **RP2350 idle is a plain `__wfi`.** Master keeps every clock running in
  sleep (`SLEEP_EN0/1` = reset value). NS cannot write CLOCKS, so it skips
  that write and depends on the registers still being all ones. The monitor
  must never narrow them.
- **Startup and heap.** `ports/rp2040/main.c` sizes the Ruby heap from the
  linker symbols `end` .. `__StackLimit` (no `heap_pool[]`), sets a C stack
  floor from `__StackBottom`, and reports a dead main task through
  `report_startup_error()` → `abort()`, which lands in `ns/exit_ns.c`. The
  branch's `mrb_protect_error` scheduler wrapper is gone.
- **VM shape.** `MRB_INT32` + `MRB_WORD_BOXING` + `MRB_USE_C_STACK_CHECK`,
  hard-coded on the CMake side. The `-tz` build configs are now generated
  as "stock config minus psg (and BLE on the W) plus mbedtls" and must stay
  that way: any other define or gem set does not match the port objects.
- **pico-sdk 2.3.0**, no pico-extras, no `picoruby-net`, and R2P2's CMake
  takes `mrbc` from `build/<config>/bin/mrbc` (no host build needed first).

## What changed on the TZ side

| Area | Change |
|---|---|
| `ns/sleep_ns.c` | Wraps master's `Machine_sleep_timer` / `Machine_sleep_gpio` (the old `Machine_sleep(seconds)` is gone). See the table below. |
| `ns/ns_build.cmake` | Wrap list updated. Three startup stages that `pico_low_power` adds in SDK 2.3.0 are disabled for NS: `low_power_reboot_check` (reads POWMAN before `main` → BusFault), `low_power_cache_unpin`, `rp2350_sleep_fix`. |
| `ns/memmap_r2p2_ns.ld` | `.scratch_x` / `.scratch_y` moved below `end`. With the heap starting at `end`, anything placed after it would be overwritten. Both are empty in today's builds, so this was latent. |
| `monitor/main.c` | `accessctrl_hw->adc0` → `adc` (renamed in SDK 2.3.0, same register). |
| `build_config/*-tz.rb` | Regenerated from the stock configs. |
| picoruby-machine `machine.c` | TZ guards kept: skip the `SLEEP_EN` writes, enable `USBCTRL_IRQ`. The bring-up `gpio_init(25)` was dropped (GP25 is the CYW43 chip select on the W). |

### `Machine.sleep` under TrustZone

Master's API is `Machine.sleep(deep:, source:, ...)`. NS can offer:

| Call | Under TZ |
|---|---|
| `deep: true, source: :timer, ms:` | `sg_deep_sleep` for `ms / 1000` whole seconds, then the remainder awake. `ms < 1000` raises `ArgumentError`. USB detaches and re-enumerates, as before. `Time.now` is corrected by the Secure AON timer's delta. |
| `deep: false, source: :timer, ms:` | A plain blocking wait. No power saving. |
| any GPIO source | `NotImplementedError`. The veneer menu has no GPIO wake state. |

A veneer refusal (busy, or core 1 running) now raises `RuntimeError`
instead of silently waiting awake.

## Behavior that changed for stock WiFi builds on this branch

Because master is poll mode too, three branch changes that used to apply
only to TZ now apply to every WiFi build on this branch: `Net_busy_wait_ms`
polls for the whole wait; the CYW43 LED loopback probe is a warning
(`CYW43._init_error`), not an init failure; `enable_sta_mode` selects
`CYW43_PERFORMANCE_PM`. Revisit before upstreaming any of them.

## Verification status

Toolchain: arm-none-eabi-gcc 14.2.1, pico-sdk 2.3.0, picotool 2.3.0.

| Check | Status |
|---|---|
| Stock `pico2:prod`, `pico2_w:prod` build | pass (2026-11-25) |
| Monitor builds, 19 veneers in the implib (pico2, pico2_w) | pass |
| NS `pico2:prod` links; no `low_power_*` / `powman_*` code; startup stage list equals the SDK 2.2.0 set | pass |
| NS `pico2_w:prod` links; no btstack | pass |
| `r2p2:tz:package` (unsigned), manifest size + SHA-256 correct | pass |
| Boots to the shell on a Pico 2 (chip `F285090F83A9FB62`, blank OTP, unsigned package) | pass (2026-11-25) |
| `TZ.selftest` returns `true` | pass (2026-11-25) |
| `__wfi` idle wakes under TZ (shell stays responsive) | shell and irb usable; not timed separately |
| `Machine.sleep(deep: true, source: :timer, ms: 3000)` naps and wakes | pass (2026-11-25) |
| Second boot of the same firmware skips the system-file refresh (flash filesystem writes under TZ landed) | pass (2026-11-25) |
| Raise in `main_task` halts in `exit_ns.c` | **not yet run** |
| Pico 2 W: WiFi join, socket round-trip, long-idle RX | **not yet run** (no W board at hand) |
| esp32 port still builds | not checked (no toolchain) |

First boot after the reflash printed `Found: <path> ... CRC mismatch,
Writing N bytes` for system files. That is `Shell.setup_system_executables`
refreshing the executables stored on the flash filesystem because the
firmware's `RUBY_DESCRIPTION` changed; it is stock master behavior and runs
once per firmware change. A second boot of the same firmware printed none
of it (checked 2026-11-25), so every write landed. Should the lines ever
repeat on an unchanged firmware, a write failed and the filesystem path
under TZ needs another look (`WIFI-UNDER-TZ-HANDOFF.md`, "Open bug 2").

## Open items

- The monitor's own deep-sleep recipe was verified on SDK 2.2.0. SDK 2.3.0
  ships an "RP2350 sleep fix" stage in `pico_low_power` (a dummy WFI after
  a watchdog reboot). NS skips it; decide whether the monitor needs it.
- `sg_deep_sleep` counts seconds. A millisecond state would let the wrap
  drop the awake remainder and the 1000 ms floor.
- No GPIO wake state in the veneer menu.
- The README's gem table and the older handoff docs still describe the
  pre-sync mechanisms (task-switch hook, TZ-only poll mode).
