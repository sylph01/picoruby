# R2P2-TZ OTP burn recipe (board 1 only) — IRREVERSIBLE

Every write below is permanent (OTP fuses only go 0→1). **Board 1 only**
(pristine Pico 2, chip ID `561F0E08F528C156`); board 2 has a burned
BOOTKEY and must never be used here. Confirm identity first:

```sh
picotool otp dump | head -1   # rows 0..3 low halfwords must read 561f 0e08 f528 c156
picotool otp get CRIT1        # must be 0 (secure boot not yet enabled)
picotool otp dump | grep '^0080:'   # BOOTKEY0 must be all-zero
```

Secrets live off-repo in `~/.r2p2-tz-keys/` (never committed):
`boot_signing.pem` (secp256k1 boot key), `device_root.bin`,
`gateway_psk.bin`. The signed artifacts are produced by
`R2P2_TZ_SIGKEY=~/.r2p2-tz-keys/boot_signing.pem rake r2p2:tz:package`,
which emits `package/bootkey_otp.json` (BOOTKEY fingerprint + KEY_VALID).

The three groups are independent and increase in danger. Do them in
order; **stop and re-verify boot between B and C.**

## Precondition (already satisfied, keep it true)

The real-signed combined image must boot on board 1 with secure boot
still OFF — proven repeatedly before touching group C. If you rebuild,
re-verify.

> **Burn log — board 1 (chip ID `561F…`), 2026-07-07. FULLY SEALED.**
> - A: keys provisioned to pages 48/49, "Verified OK", keystore off
>   dev-fallback (`TZ.derive_key` fingerprint changed), selftest PASSED.
>   GATEWAY_PSK is a random placeholder, now permanent.
> - B+C: `otp load bootkey_otp.json` burned BOOTKEY0 + KEY_VALID **and**
>   SECURE_BOOT_ENABLE in one shot (the JSON bundled crit1 — see below).
>   Debug left enabled. Board rebooted and booted the signed image under
>   enforcement in ~2s; selftest PASSED. Board 1 now boots ONLY the
>   boot_signing.pem-sealed image; flash it via `picotool load
>   <sealed-combined.uf2>` in BOOTSEL.

## A. Provision keystore keys (irreversible, NON-bricking)

Switches the keystore from chip-ID dev fallback to real OTP keys. ECC
rows, 2 bytes/row, 16 rows = 32 bytes each; page 48 = row 0xc00, page
49 = row 0xc40 (matches `monitor/keystore.c`).

```sh
picotool otp load -e -s 0xc00 ~/.r2p2-tz-keys/device_root.bin
picotool otp load -e -s 0xc40 ~/.r2p2-tz-keys/gateway_psk.bin
# optional hardening — make the pages hardware read-only forever
# (the monitor already ratchets SW_LOCK per boot; this is the fuse form):
# picotool otp set -e PAGE48_LOCK0 0x3f   # R/W -> no access after boot
# picotool otp set -e PAGE49_LOCK0 0x3f
```

Verify: reboot, `TZ.selftest` still PASSED, and the keystore is no longer
in dev-fallback (a chip-ID-independent HMAC now — cross-check with a host
recompute if desired). GATEWAY_PSK here is a random placeholder; in a real
deployment write the value shared with the server instead.

## B. Burn the BOOTKEY fingerprint (irreversible, NON-bricking alone)

**CRITICAL — B and C are NOT separable via this JSON.** `picotool seal
--sign` writes a `crit1: { secure_boot_enable: 1 }` block into
`bootkey_otp.json` *in addition to* `bootkey0` + `key_valid`. So

```sh
picotool otp load package/bootkey_otp.json
```

applies BOTH the BOOTKEY *and* SECURE_BOOT_ENABLE in one shot — this line
**is the point of no return**, not a non-bricking step. (Confirmed on
board 1, 2026-07-07: the load echoed `crit1: secure_boot_enable:
0x00000001` and CRIT1 read back 0x1 immediately.) It does NOT set the
debug-disable bits, so SWD survives unless you add them.

If you genuinely want B alone (fingerprint now, enable later), strip the
`crit1` key from the JSON first:

```sh
python3 -c "import json;d=json.load(open('package/bootkey_otp.json'));d.pop('crit1',None);json.dump(d,open('bootkey_only.json','w'))"
picotool otp load bootkey_only.json      # BOOTKEY + KEY_VALID only, non-bricking
```

Verify either way:

```sh
picotool otp dump | grep '^0080:'          # BOOTKEY0 now non-zero
picotool otp get BOOT_FLAGS1               # KEY_VALID = 1
picotool otp get CRIT1                      # SECURE_BOOT_ENABLE: 1 if the full JSON was used
```

## C. Enable secure boot (IRREVERSIBLE and BRICK-CAPABLE)

Already done by the full-JSON load in B above. Only needed separately if
you used the stripped `bootkey_only.json`:

```sh
# optionally disable debug FIRST (ends SWD/probe access forever — omit to
# keep the probe working on a dev secure-boot board):
# picotool otp set -e CRIT1 0x2          # SECURE_DEBUG_DISABLE (bit 1)
# picotool otp set -e CRIT1 0x4          # DEBUG_DISABLE (bit 2)

picotool otp set -e CRIT1 0x1            # SECURE_BOOT_ENABLE (bit 0) — no return
```

After enabling: power-cycle and confirm the board still boots the signed
image. From now on every flash must be the full sealed package loaded in
BOOTSEL; an unsigned dev build is rejected by the mask ROM.

## If you keep debug (SWD) enabled

Leaving CRIT1 debug bits clear keeps the probe working (tz_diag reads,
gdb) after secure boot — fine for a development secure-boot board, not for
a shipped one. Decide per board. **Board 1 (chip `561F…`) is intentionally
kept this way — a debug board.** The section below is for a *different*,
production board.

---

# Hardened production board (full lockdown)

Everything above (A + B/C) makes the monitor non-bypassable but leaves the
key rows **readable** — on board 1 they can still be dumped with
`picotool otp dump` in BOOTSEL, and read via SWD. That's fine for a debug
board; it is not fine for production. This section adds the locks that
close those paths. Do it on a FRESH board, not board 1.

## Threat model — what each control actually stops

| Attacker | Stopped by |
|---|---|
| Compromised NS runtime / remote malware | Already stopped by secure boot + the TZ partition (NS can't address OTP, can't read SRAM8/9, only sees veneers). No OTP locks needed for this. |
| Physical, USB + `picotool otp dump` in BOOTSEL | **Page LOCK_BL** (deny bootloader read of the key pages). |
| Physical, NS-side bus read | **Page LOCK_NS** (already covered at runtime by the SW_LOCK ratchet + ACCESSCTRL; the fuse makes it permanent). |
| Physical, SWD debug probe (reads OTP, or the derived keys from SRAM) | **CRIT1 debug-disable.** This is the dominant control — OTP locks are useless while debug is on. |
| Invasive lab (decap / microprobe / glitch) | **CRIT1 glitch detectors**, and architecturally per-device keys so one extracted board doesn't scale. Residual risk remains; don't put irreplaceable secrets on the MCU. |

## Ordering rules (why this sequence)

- Keys are **written before** the page locks — `picotool otp load` uses the
  bootloader, which LOCK_BL is about to forbid.
- Debug-disable is **dead last**, after secure boot is proven to boot,
  because it ends your only window to diagnose a bad burn.
- Verify (boot + `TZ.selftest`) **between** each irreversible group while
  debug still works.
- Key pages get `LOCK_S = read-only`, never inaccessible — the monitor
  must still read them at boot (`ks_init`). Inaccessible → keystore fails
  → `diag_halt`.

## P1. Provision REAL keys (pages 48/49)

Same as group A, but with production key material: a **per-device random**
DEVICE_ROOT (unique per board) and the **real server-shared** GATEWAY_PSK
(not the random placeholder board 1 got).

```sh
picotool otp load -e -s 0xc00 device_root_<serial>.bin   # unique per board
picotool otp load -e -s 0xc40 gateway_psk.bin            # real shared PSK
```
Boot, confirm `TZ.selftest` PASSED. (Last chance to read these back with
`picotool otp dump` for your provisioning records — after P2 you can't.)

## P2. Lock the key pages (deny NS / bootloader; Secure read-only)

Field selectors let picotool handle the rows' 3-way majority-vote
encoding — do not hand-write raw row values. LOCK states are
thermometer-coded (advance-only), so these are permanent.

```sh
# page 48 (DEVICE_ROOT)
picotool otp set PAGE48_LOCK1.LOCK_S  0x1   # Secure read-only (monitor still reads)
picotool otp set PAGE48_LOCK1.LOCK_NS 0x3   # Non-secure: no access
picotool otp set PAGE48_LOCK1.LOCK_BL 0x3   # bootloader (picotool): no access
# page 49 (GATEWAY_PSK)
picotool otp set PAGE49_LOCK1.LOCK_S  0x1
picotool otp set PAGE49_LOCK1.LOCK_NS 0x3
picotool otp set PAGE49_LOCK1.LOCK_BL 0x3
```
Rollback counter (page 50): if the monitor is built `R2P2_TZ_OTP_WRITE=1`
it must keep WRITING page 50, so leave `LOCK_S = 0x0` there and only lock
out NS/BL (`PAGE50_LOCK1.LOCK_NS 0x3`, `.LOCK_BL 0x3`). If rollback is
unused, lock it like the key pages.

Verify: reboot, `TZ.selftest` still PASSED (proves the monitor still reads
the pages under LOCK_S=read-only). `picotool otp dump` of 0xc00/0xc40 in
BOOTSEL should now be refused — that's the point.

## P3. Glitch detectors

```sh
picotool otp set CRIT1.GLITCH_DETECTOR_ENABLE 0x1
# optional: raise sensitivity (0..3) — test for spurious resets first
# picotool otp set CRIT1.GLITCH_DETECTOR_SENS 0x1
```
Reboot and confirm stable boot (an over-sensitive detector can reset a
clean board).

## P4. BOOTKEY + secure boot

As B/C above — `picotool otp load bootkey_otp.json` (bundles BOOTKEY +
KEY_VALID + SECURE_BOOT_ENABLE). Reboot, confirm the signed image boots
under enforcement, `TZ.selftest` PASSED. **Do not disable debug yet** —
you still want it if the next reboot misbehaves.

## P5. Disable debug (LAST — irreversible, ends SWD forever)

Only after P4 boots cleanly. After this there is no probe, no gdb, no
`tz_diag` over SWD on this board, ever.

```sh
picotool otp set CRIT1.SECURE_DEBUG_DISABLE 0x1   # bit 1
picotool otp set CRIT1.DEBUG_DISABLE        0x1   # bit 2
```
Power-cycle. If it boots the signed image, the board is fully locked. If
it doesn't, it's a brick with no recovery — which is why every prior group
was verified first.

## P6. (Optional) close boot paths — BOOT_FLAGS0

Hardening vs. field-recoverability tradeoff. With secure boot on, the USB
picoboot path only loads *signed* images, so keeping it enables signed
field updates; disabling it removes that. Disable UART boot if unused:

```sh
# picotool otp set BOOT_FLAGS0.DISABLE_BOOTSEL_UART_BOOT 0x1
# picotool otp set BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC 0x1   # blocks signed reflash too
```

## Production provisioning summary (one board, in order)

1. P1 real keys → verify boot
2. P2 lock key pages (S=ro, NS=no, BL=no) → verify boot + dump refused
3. P3 glitch detectors → verify stable boot
4. P4 BOOTKEY + secure boot → verify enforced boot
5. P5 debug disable → verify enforced boot (point of no diagnosis)
6. P6 optional boot-path disables

Each device needs its own `device_root_<serial>.bin`; GATEWAY_PSK is the
shared value your server holds. Keep those off-repo, per the top of this
file.
