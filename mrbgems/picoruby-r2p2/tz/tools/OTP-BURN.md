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

Applies `bootkey0` (SHA-256 of the boot key's public point) and
`BOOT_FLAGS1.KEY_VALID` from the seal JSON. Non-bricking on its own — the
mask ROM only *enforces* it once C sets SECURE_BOOT_ENABLE.

```sh
picotool otp load package/bootkey_otp.json
# verify it took:
picotool otp dump | grep '^0080:'          # BOOTKEY0 now non-zero
picotool otp get BOOT_FLAGS1               # KEY_VALID = 1
```

**Re-verify the signed image still boots here** (secure boot is still off,
so a bad key burn is still recoverable via BOOTSEL at this point).

## C. Enable secure boot (IRREVERSIBLE and BRICK-CAPABLE)

After this the mask ROM boots ONLY an image whose signature matches
BOOTKEY0. A wrong/again-corrupt image = dead board with no BOOTSEL
recovery. Do C only after B is verified and the signed image boots.

```sh
# disable debug first (optional but recommended for a real secure device;
# note: this also ends SWD access for future diag reads):
# picotool otp set -e CRIT1 0x2          # SECURE_DEBUG_DISABLE (bit 1)
# picotool otp set -e CRIT1 0x4          # DEBUG_DISABLE (bit 2)
# close unused boot paths (optional):
# picotool otp set BOOT_FLAGS0 ...       # DISABLE_BOOTSEL_UART_BOOT etc.

# the point of no return:
picotool otp set -e CRIT1 0x1            # SECURE_BOOT_ENABLE (bit 0)
```

Then power-cycle and confirm the board still boots the signed image. From
now on every flash must be the full sealed package; an unsigned dev build
will be rejected by the mask ROM.

## If you keep debug (SWD) enabled

Leaving CRIT1 debug bits clear keeps the probe working (tz_diag reads,
gdb) after secure boot — fine for a development secure-boot board, not for
a shipped one. Decide per board.
