# WiFi under TrustZone — hand-off

Written 2026-07-07 at the end of phase 2. Entry point for bringing up the
CYW43 WiFi (Pico 2 W) inside the Secure/Non-secure split. Read
`../README.md` (esp. the "hard-won facts" and the ACCESSCTRL section) and
`PHASE2-COMMIT-WALKTHROUGH.md` first; this document is only *what to do
next* and *what to watch out for*. The plan is to do this **before** the
`PHASE2-BACKLOG.md` items — and that ordering is sound, because WiFi does
**not** depend on the core-1 veneer (see §"Why this doesn't need core 1").

## Where things stand — what already works in your favor

Phase 1/2 left the boundary unusually WiFi-ready. The CYW43 driver needs
GPIO 23/24/25/29, a PIO block, DMA, a host-wake IRQ, entropy, and a
timer — and almost all of that is already granted:

- **ACCESSCTRL** (`tz/monitor/main.c` `partition_configure`): PIO0/1/2,
  DMA, `io_bank0`/`pads_bank0`, and **all user GPIO** are NS
  (`gpio_nsmask[0] = 0x3fffffff` = GP0–29, which includes the four CYW43
  pins). PIO IRQs 0/1 for all three PIOs are already in `tz_ns_irqs[]`
  (ITNS-routed NS). 12 DMA channels (0–11) are NS.
- **Entropy for TLS** is done: `pico_mbedtls.c`'s `mbedtls_hardware_poll`
  is linked and its `get_rand_64()` is `--wrap`ed to `sg_random_bytes`
  (phase-2 commit `dea0c911`). So mbedTLS session crypto has a
  Secure-TRNG source with no new work.
- **NS timer** path (TIMER0 + `ns/aon_ns.c`) backs `pico_time`/lwIP
  `sys_now` and the alarm pool.
- **The LED is off on the 2 W** by build flag (`R2P2_TZ_LED_DIAG=0`), so
  `led_init`/`led_set` are no-ops and GP25 (the CYW43 chip-select) is free.
- **The non-TZ WiFi build already exists**: `cmake/CMakeLists.txt`'s
  `USE_WIFI` path links `pico_cyw43_arch_lwip_threadsafe_background`,
  `pico_btstack_*`, and the cyw43 gem ports. R2P2 runs WiFi on a plain
  Pico 2 W today. The task is to make that path and the TZ path coexist.
- **picoruby-mbedtls** is already in the pico2 build config (phase 2), so
  TLS is available NS-side.

The clock contract (`r2p2_tz_config.h`) reports clk_sys = 150 MHz to NS,
which is what cyw43's PIO clock divider reads via `clock_get_hz`.

## Board

Use a **Pico 2 W with pristine OTP** — NOT board 1 (a non-W Pico 2, and
sealed). The Pico 2 W used for probe diagnostics is a candidate **iff its
OTP is still pristine** (we never burned it — confirm with `picotool otp
dump | head -1` / `picotool otp get CRIT1`). Keep it unsealed during WiFi
bring-up so plain cmake builds stay bootable; combining WiFi with secure
boot comes last.

## The work, in dependency order

### 1. Build plumbing (lift the pico2-only guard)

- `cmake/CMakeLists.txt:292` hard-errors `R2P2_TRUSTZONE` on anything but
  `pico2`. Extend it to accept `pico2_w`, and enable `USE_WIFI` for the
  `pico2_w` TZ build.
- Add a `build_config/r2p2-picoruby-pico2_w.rb` TZ variant (mirror the
  pico2 one; the non-TZ pico2_w config already exists).
- Build the **monitor** for the W: `PICO_BOARD=pico2_w` and
  `-DR2P2_TZ_LED_DIAG=0` (mandatory — see watch-out #1). The monitor
  itself uses no WiFi; it only needs to grant the right peripherals (it
  already does) and not touch GP25.
- Confirm `tz/ns/ns_build.cmake` and the memory map (`ns/memmap_r2p2_ns.ld`)
  still fit with cyw43+lwIP+TLS linked (bigger NS image; watch flash and
  the `.ns_manifest` size).

### 2. Async model — decide poll vs. threadsafe-background

The cmake currently uses `pico_cyw43_arch_lwip_threadsafe_background`,
which drives the cyw43 event loop from a **spare NVIC "user" IRQ** plus the
alarm pool. Under TZ that spare IRQ must be **added to `tz_ns_irqs[]`**
(ITNS) or cyw43 events silently never fire. The IRQ number is claimed
dynamically (`user_irq_claim_unused`), so you must pin it (claim a known
spare IRQ) and route exactly that one NS.

**Recommended: evaluate `cyw43_arch_poll` mode first.** Polling
(`cyw43_arch_poll()` called from R2P2's cooperative scheduler loop) fits
the "single NS caller, cooperative scheduler, veneers are blocking C
calls" model the whole design already assumes, and it sidesteps the
spare-IRQ routing entirely. Cost: you wire `cyw43_arch_poll()` into the
scheduler and accept a little more latency. Fall back to background+ITNS
only if poll can't keep up.

### 3. Pre-main constructor audit (hard-won fact #4)

The phase-1 NS runtime-init trimming exists precisely because SDK/gem code
touches Secure-only peripherals before `main`. cyw43_arch/lwip/btstack are
new surface. `cyw43_arch_init()` is an explicit call (good), but grep the
pulled-in objects for `__attribute__((constructor))` and for direct
CLOCKS/PLL/POWMAN/PSM access. cyw43 *should* only read clk_sys via
`clock_get_hz` (NS override handles it) and drive PIO/GPIO/DMA — but verify.
Any pre-main Secure access faults into the monitor; `tz_diag` @0x20080000
(over SWD — the probe still works on this board) will name the PC.

### 4. Bring-up ladder (each rung is a checkpoint)

1. `cyw43_arch_init()` succeeds (loads the CYW43 firmware blob over PIO
   SPI — pure GPIO/PIO/DMA, no Secure access).
2. Scan / join an AP; read the MAC.
3. DHCP lease (lwIP up, timers working).
4. Plain TCP to a host.
5. TLS via mbedTLS (entropy already wired) — the real goal for a gateway.

Drive from irb over USB CDC, same as `TZ.selftest`. Faults land in
`tz_diag`; read with `tools/tz_diag.gdb`.

## Why this doesn't need core 1

`threadsafe_background` (and poll) run the cyw43 async context on **core 0
via IRQ/polling, not a second core** — so WiFi does **not** require
`sg_launch_core1_ns` (a `PHASE2-BACKLOG` item). This is why doing WiFi
before the backlog works. (psg/pitchdetector are the things that want
core 1; WiFi is independent.) If you later move cyw43 to core 1 for
throughput, *then* you need the core-1 veneer and the veneer reentrancy
guards first.

## Watch-outs

1. **Never build the 2 W monitor with `R2P2_TZ_LED_DIAG=1`.** GP25 is the
   CYW43 chip-select; the LED path would drive it and fight the driver.
   The default is ON (for board 1), so the W build must explicitly set 0.
2. **The async background IRQ must be NS-routed** (§2) or cyw43 hangs with
   no error — a silent failure, not a fault. Poll mode avoids this.
3. **DMA channel exhaustion.** cyw43 claims ~2 channels dynamically; NS
   owns 0–11. If R2P2's other DMA users (psg, etc.) plus cyw43 exceed 12,
   a claim lands on a Secure channel → fault. Count usage; if tight, raise
   `TZ_NS_DMA_CHANNELS` (RP2350 has 16; the monitor needs none, so NS can
   have all 16) in `r2p2_tz_config.h` and re-grant in `partition_configure`.
4. **RAM budget.** lwIP + an mbedTLS TLS session is heap-hungry. The 2 W
   has 520 KiB SRAM (NS gets the bulk), but watch `HEAP_SIZE_KB` and TLS
   handshake buffers. Measure a full TLS handshake.
5. **Bluetooth.** The `USE_WIFI` cmake also pulls `pico_btstack_*`. If you
   only want WiFi, try to drop BT to save RAM/complexity (the combined
   CYW43 firmware still contains both, but you needn't link the host
   stack).
6. **Keep OTP pristine** on the WiFi dev board until WiFi works; only then
   fold in secure boot (and remember the 2 W's LED is on the CYW43, so the
   `tz_diag`/probe channel — not the LED — is your diagnostic there
   regardless).

## Open questions to settle early

- Poll vs. background (§2) — decides whether you touch ITNS at all.
- WiFi-only vs. WiFi+BLE (watch-out #5) — decides RAM and link set.
- Which spare IRQ to pin if you keep background mode.
- Whether the gateway use-case needs the server-shared `GATEWAY_PSK`
  provisioned for real (a fresh board + the `OTP-BURN.md` production path),
  or dev-fallback keys suffice during bring-up (they do).
