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

---

## Status update (2026-07-07, end of bring-up session 1)

Everything above §"The work" is DONE and hardware-verified on the
pristine-OTP Pico 2 W (commits 199d1848..6d7859a0):

- Build plumbing (§1), **poll mode** chosen (§2 — the net/socket gems
  were already coded for it; stock+poll verified working on hardware, so
  poll is exonerated of everything below), constructor audit (§3) clean.
- **Ladder: rungs 1–3 PASS under TZ** — `CYW43.init` → STA → WPA2 join →
  full DHCP handshake (lease acquired from a host-side `nmcli` hotspot),
  cold boot, no debugger. Rung 4 (TCP) blocked by the RX-pump bug below.

### The big find: NS pad writes never land (fixed in monitor)

NS writes to PADS_BANK0 are silently dropped (SDK pad writes all go via
the atomic aliases; IO_BANK0 FUNCSEL plain writes DO work) → every pad
stays reset: ISO latched, IE clear → no NS-configured pin ever drives.
The monitor now de-isolates + input-enables all NSMASK'd bank-0 pads
(`partition_configure`, commit 5cdf1961). Without this, ALL pad-touching
NS peripherals (UART/I2C/SPI/PWM/WiFi) are dead while looking configured.
Diagnosis tools that earned their keep: `CYW43._probe_up` (forces
ensure_up, returns its real error; -6 EIO = SPI garbage), `CYW43._state`,
SWD dumps of ACCESSCTRL (all grants were correct!) and of PADS (0x116 =
reset+ISO = the smoking gun). TODO: datasheet check — aliases-only vs all
pad writes; decides whether NS runtime pull/drive changes need a veneer.

### Open bug 1: async F2 RX delivery stalls at idle (blocks rungs 4–5)

TX works; the AP's DHCP replies arrive OTA but sit undelivered — every
synchronous ioctl drains them (a `CYW43::GPIO#read` pump loop completes
DHCP instantly; that's how rung 3 was proven). So `cyw43_arch_poll()` at
idle isn't processing packets: suspect `cyw43_ll_has_work` →
`gpio_get(24)` (host-wake pin) reading 0 from NS, or the LEVEL_HIGH GPIO
IRQ on pin 24 not firing NS. Next session: read SIO_NS GPIO_IN bit 24
while packets are pending; if dead, either fix the input path or make the
50 ms sleep-check worker call process_packets unconditionally.
Also observed: board TX frames appear DUPLICATED in AP-side tcpdump
(firmware ACK-timeout retries? benign so far, worth understanding).

### Open bug 2: littlefs corruption on the seeded FS (TZ only)

Fresh-format + same-boot small write/readback both PASS; but a boot
sequence seeding the system executables can corrupt the FS such that
later boots fail `Corrupted @ lfs_file_read` — and a corrupted volume
can HANG littlefs (boot task freezes pre-shell). Fresh-erase clears it
(`picotool erase -r 0x10340000 0x10400000`; note littlefs actually lives
at 0x380000+, `LFS_FLASH_TARGET_OFFSET` ≠ cmake's `FLASH_TARGET_OFFSET`).
Suspect multi-KB / multi-sector write paths under checked_flash_op.
Unrelated to pads (QSPI is Secure-side).

### Operational gotchas (hard-won today)

- After `picotool load`, `picotool reboot` often leaves the board dark —
  ask for a **physical replug** instead. BOOTSEL + `picotool load -v` is
  the reliable flash path; openocd `program ... verify reset exit` works
  but ALWAYS pass verify (an unverified program once left a corrupt,
  dark-booting image). Avoid openocd RESCUE unless truly bricked.
- The boot-error loop-print (main_task rescue) + `tio`-style capture
  beats racing USB enumeration; never hold a CDC fd across a board reset
  (it can wedge the host kernel's USB stack — hard reboot territory).
- 802.11-level join state is visible host-side: `iw dev <ap-if> station
  dump` (associated/authorized), NM-dnsmasq leases need sudo, tcpdump on
  the hotspot interface is the ground truth for DHCP.

### Ladder remainder for next session

4. TCP to a host — echo server script exists (scratchpad
   tcp_echo_server.py, port 4444; host is 10.42.0.1 on the hotspot).
5. TLS via mbedTLS — self-signed P-256 cert generated; measure RAM
   during handshake (watch-out #4).
Fix RX pump first; both rungs then likely just work.

---

## Status update (2026-07-07, session 2): LADDER COMPLETE — rungs 1–5 PASS

Commit 40171f77 fixed open bug 1; all five rungs now pass on the
pristine-OTP Pico 2 W under TZ, cold boot, no debugger, no pump loop.

### Open bug 1 SOLVED: bank-0 GPIO IRQs are split per security domain

Datasheet §10.6.1, last bullet-but-two: interrupts for an NSMASK'd pin
assert **IO_IRQ_BANK0_NS (IRQ 22)**, never IO_IRQ_BANK0 (21). All 30
user pins are NSMASK'd, so from NS the _NS line is the only one that
ever fires — and the TZ-unaware SDK wires handlers + NVIC enables to 21.
The cyw43 host-wake LEVEL_HIGH event (the thing that marks the poll
worker pending once the 500 ms bus-sleep countdown dies) pended
invisibly on Secure-targeted line 22 forever. Hence: TX fine, RX
undelivered until any synchronous ioctl drained F2.

Fix (commit 40171f77): monitor ITNS-routes IRQ 22; `ns/gpio_irq_ns.c`
provides a strong `isr_irq22` that forwards to IRQ 21's vtable handler
(looked up per-fire — SDK handler add/remove keeps working) and enables
NVIC 22 from a pre-main constructor. This fixes **all** NS GPIO
interrupt users, not just cyw43 (picoruby-gpio IRQs would have hit the
same wall).

Proof of idle delivery (not poll-window luck): TCP segment pushed by the
host 6 s into a pure Ruby `sleep` (bus asleep, zero socket calls) was
ACKed by the board's lwIP in **261 ms** (host-side TCP_INFO
tcpi_unacked; scratchpad late_push_server.py).

### Session-1 pads TODO also resolved: it's erratum RP2350-E3

"NS pad writes never land" was never aliases-vs-plain: on QFN-60
(RP2350A) the per-pin NS gating of PADS_BANK0 uses the WRONG
GPIO_NSMASK bits (the QFN-80→60 pad remap was left out of the
permission wiring; fixed in A4 stepping). With our nsmask, pads 0–17
happen to be NS-writable and 18–29 (incl. all four CYW43 pins) silently
RAZ/WI. The monitor-side pad init is exactly the erratum's prescribed
workaround; when a gem needs runtime pull/drive changes from NS, add an
`sg_pad_write` veneer (E3 workaround, second half). Full comment in
`partition_configure`.

### Verified this session (hardware, cold boot)

- Rung 3 re-run with NO pump: join → `sleep 8` idle → LINK_UP (DHCP
  lease 10.42.0.106 from the nmcli hotspot).
- Rung 4: `TCPSocket` echo round-trip to 10.42.0.1:4444.
- Rung 5: `SSLSocket` (verify NONE, self-signed P-256 server cert) —
  TLS 1.2 ECDHE-ECDSA-AES128-GCM-SHA256 handshake + echo + clean close.
  No OOM at current HEAP_SIZE_KB; fine-grained C-heap high-water
  measurement (watch-out #4) still worth doing before the gateway work.
- littlefs (open bug 2): the seeded-FS boot after a fresh
  `picotool erase -r 0x10340000 0x10400000` came up clean this time
  (bin executables all present). Bug remains open — it was never
  root-caused, only not reproduced today. Watch it across reboots.

### Still open / next

- Open bug 2 (littlefs corruption under TZ) — unreproduced today but
  un-root-caused; suspect multi-sector writes under checked_flash_op.
- TX frames duplicated in AP-side tcpdump (session 1 observation) —
  benign so far, not re-checked this session.
- `sg_pad_write` veneer when a gem needs NS runtime pad changes (E3).
- Soak: long-idle RX (minutes-hours), repeated join/leave, reboot
  persistence of the FS.
- Then: PHASE2-BACKLOG items and folding in secure boot (OTP still
  pristine on this board).

Ruby-side driving recipe (irb over CDC): `CYW43.init("JP")` →
`CYW43.enable_sta_mode` → `CYW43.connect_timeout(ssid, psk,
CYW43::Auth::WPA2_MIXED_PSK, 10)` → `CYW43.link_connected?(true)`;
sockets are stock `TCPSocket` / `SSLContext`+`SSLSocket.open`.
NB: the dev hotspot PSK used in session 2 should be rotated (it leaked
into a terminal transcript via irb character echo).
