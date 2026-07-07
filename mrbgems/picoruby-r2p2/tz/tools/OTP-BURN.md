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
a shipped one. Decide per board.
