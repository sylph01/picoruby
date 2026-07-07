# Phase 2 commit walkthrough — TrustZone-partitioned R2P2

Written 2026-07-07 for explaining the `trustzone-sketch-2` branch (16
commits, `aedd1026..720dee18`, all 2026-07-07) to PicoRuby maintainers.
It is the sequel to `PHASE1-COMMIT-WALKTHROUGH.md` and assumes that
document's primer — Secure/Non-secure split, IDAU/SAU, ACCESSCTRL,
veneers, the bootrom-as-participant, linker `--wrap` — is already read.
Phase 1 built the *partition* (a Non-secure mruby VM launched by a Secure
monitor) and proved a handful of veneers. Phase 2 fills the boundary with
real content: a keystore backed by OTP, a symmetric-crypto core, signed
bytecode verification, the Non-secure Ruby API that consumes all of it,
a probe-based diagnostics channel, and finally **secure boot** — the
step that makes the whole monitor non-bypassable.

Where phase 1 was dominated by "why did the board fault" bring-up,
phase 2 is dominated by two different concerns: **keeping key material on
the Secure side of a hostile boundary** (the crypto/keystore commits) and
**not bricking a chip with a one-way fuse write** (the OTP commits). The
document is organized in five parts, each a coherent chunk of that story:

- **Part I — The crypto boundary** (1 commit): the keystore, the
  symmetric core, the veneer wiring, and `sg_verify_mrb`. One large
  commit; most of the phase's design lives here.
- **Part II — Proving it on hardware** (3 commits): the on-target
  self-test and the two fixes it forced.
- **Part III — The Ruby surface** (5 commits): `Digest::SHA256`,
  `TZ.derive_key`, `TZ.verify_mrb`, and the mbedTLS build integration
  that turned out to be most of the work.
- **Part IV — Probe-first diagnostics** (3 commits): retiring the LED
  "morse code" from phase 1 for an SWD-readable record (item 0 of the
  hand-off).
- **Part V — Secure boot** (4 commits): the reversible rehearsal, then
  the irreversible OTP burns, on real hardware.

---

## Primer: the seven ideas phase 2 adds

**1. Two key tiers, and what may cross the boundary.** The security model
is that *key material never crosses the veneer boundary* — Non-secure
code holds opaque `sg_key_t` handles, never bytes. The single deliberate
exception is `sg_key_derive_export`: it runs HKDF on a parent key and
writes the *derived* result to NS memory. That is the "tier-2" model — an
NS compromise reveals a short-lived session key, never the parent it came
from. Everything in the keystore is arranged around that one asymmetry.

**2. The keystore is an OTP-rooted tree.** RP2350's OTP (one-time
programmable fuses) has a large user area. Two 32-byte secrets live at
fixed *pages* (48 = DEVICE_ROOT, 49 = GATEWAY_PSK); the monitor reads
them once at boot, HKDF-extracts working keys, then **ratchets SW_LOCK**
so even Secure code can't reread the master pages until reset. The
slot→page map and per-slot policy live *only in the monitor image*, so an
NS rebuild can neither repoint nor repolicy a slot. When the pages are
blank (a pristine chip), the monitor derives *dev-grade* keys from the
public chip ID instead — so the entire keystore is exercisable on a fresh
board with zero fuse writes.

**3. No mbedTLS in the monitor — a symmetric slice, hand-assembled.**
The monitor has ~8 KiB of RAM total. A full TLS stack does not fit and is
not wanted in the trusted computing base. Instead the crypto core
(`sg_crypto.c`) is HMAC and HKDF written directly over the *hardware*
SHA-256 engine, and the RFC 8439 ChaCha20-Poly1305 AEAD *construction*
written over just two mbedTLS primitive files (`chacha20.c`,
`poly1305.c`) — no `md.c`, no `chachapoly.c`, no heap. ChaCha20-Poly1305
(not AES-GCM) because RP2350 has no AES hardware and ChaCha20 is
constant-time in software.

**4. Verifying a hostile buffer: TOCTOU discipline.** A veneer argument
that is a *request struct* (needed because CMSE entry functions can't take
stack-passed args) is doubly dangerous: NS can rewrite its fields *after*
the monitor validates a pointer but *before* it uses it. The rule, applied
in every wide veneer: `memcpy` the struct into Secure stack first, then
`rom_validate_ns_buffer` the copied pointers, and never re-read the NS
struct again. Bulk data buffers (the plaintext being hashed) are
different — NS racing its own message only corrupts its own result — so
those are read in place. `sg_aead_decrypt` adds a second rule: it MACs the
ciphertext and checks the tag *before* producing any plaintext, so a
forgery writes **nothing** to the NS output buffer.

**5. Signed bytecode is a policy gate, not integrity.** `sg_verify_mrb`
verifies an ECDSA-P256 signature (via vendored micro-ecc — verify-only,
all inputs public) over a small envelope, checks an OTP monotonic
rollback counter, and on success **latches** a flag that unlocks
`SG_SLOT_GATEWAY_PSK`. It attests buffer contents *at call time*; NS owns
the buffer and the VM that runs it, so this is "only a verified package
may open this key," not a guarantee about NS control flow. The private
key never leaves the signing host.

**6. OTP is one-way, and secure boot is the one bricking step.** Fuses go
0→1 only; nothing is reversible. Three independent burns, increasing in
danger: (A) provision the keystore pages — irreversible but non-bricking;
(B) burn a BOOTKEY fingerprint — the ROM ignores it until (C)
`CRIT1.SECURE_BOOT_ENABLE` makes the mask ROM verify the monitor's
signature on *every* boot. After C a wrong image is a dead board. The
whole of Part V is structured to make everything before C reversible and
provable.

**7. A monitor with no console: the diagnostic record.** Phase 1
debugged a console-less Secure monitor by blinking the LED. Phase 2
replaces that with a `tz_diag` struct at a fixed RAM address
(`0x20080000`) — boot-stage breadcrumbs plus a full fault dump — read
over SWD with the Raspberry Pi Debug Probe. The LED path survives behind
a build flag for the board that has an LED.

### Reference index

| Source | Used for |
|---|---|
| RFC 8439 | ChaCha20-Poly1305 AEAD construction + the on-target/host test vectors |
| RFC 5869 | HKDF-Extract/Expand (key derivation) + test vectors |
| RFC 4231 | HMAC-SHA256 test vectors |
| Datasheet §10.5 | Secure-boot OTP procedure (BOOTKEY, `CRIT1`, `BOOT_FLAGS`) — executed for real in Part V |
| Datasheet OTP map (`otp_data.h`) | User-content rows; CHIPID rows; `SW_LOCK` per-page registers; page-lock fuses |
| pico-sdk `pico_sha256` | Hardware SHA-256 driver — the base of HMAC/HKDF and `sg_verify_mrb`'s digest |
| pico-sdk mbedTLS 3.6 (`chacha20.c`, `poly1305.c`) | The only two crypto primitive files compiled into the monitor |
| pico-sdk `pico_mbedtls.c` | `mbedtls_hardware_poll` entropy glue for the NS-side mbedTLS gem (wrapped to `sg_random_bytes`) |
| kmackay/micro-ecc @541b3a7 (BSD-2) | Verify-only ECDSA P-256 for `sg_verify_mrb` (vendored; user-approved) |
| picotool `seal` / `otp` | Signing the monitor; reading/writing OTP; **`seal --sign` bundles `crit1` into its OTP JSON** (Part V) |
| Raspberry Pi openocd fork + Debug Probe | SWD access for the `tz_diag` record; flashing without BOOTSEL |
| picoruby-mbedtls gem | NS-side `MbedTLS::Cipher` consuming `TZ.derive_key` output (tier-2 sessions) |

A note on why ECDSA over an HMAC seal (the open question from phase 1):
HMAC would be tiny and need no new code, but it means "sealed by the fleet
key," not third-party-verifiable authorship, and it is *symmetric* — the
verifying key on the device equals the signing key, so a dev board on
blank OTP could not verify anything without first sharing a secret.
Verify-only P-256 keeps the private half on the host and works on a
pristine chip; the memory-budget objection (a full mbedTLS ECDSA wants
4–6 KiB of stack) is dodged by vendoring micro-ecc, whose verify path
measured ~1 KiB.

---

## Part I — The crypto boundary

### `ae0f4f8b` — real crypto veneers + `sg_verify_mrb`

The phase's centrepiece; every stub from phase 1 becomes real. Five new
units:

- **`sg_crypto.{c,h}`** — the symmetric core (primer §3). HMAC-SHA256 and
  HKDF are streamed over the hardware SHA-256 engine (one engine, so the
  outer HMAC hash only starts after the inner finishes — sequential
  sessions are safe). The AEAD is the RFC 8439 construction written by
  hand over `mbedtls_chacha20_*`/`mbedtls_poly1305_*`: derive the
  Poly1305 one-time key from ChaCha20 block 0, encrypt from block 1, pad
  AAD and ciphertext to 16, absorb the length block, emit the tag. Decrypt
  is deliberately two-pass (primer §4). A `SG_CRYPTO_HOST_TEST` define
  swaps the hardware SHA for mbedTLS's software one so the *exact* monitor
  code runs under host test vectors.

- **`keystore.{c,h}`** — the OTP-rooted tree (primer §2). ECC and raw OTP
  reads, blank-page detection → chip-ID dev fallback, an 8-entry
  generation-checked handle table (a stale handle to a reused slot fails
  the generation check), HKDF child derivation that drops the DERIVE
  policy bit (no unbounded chains), the SW_LOCK ratchet, and the
  thermometer-coded rollback counter whose *write* path is compiled out
  unless `R2P2_TZ_OTP_WRITE=1` — a RAM shadow keeps the semantics on dev
  boards.

- **`sg_veneers.c`** — the stubs become real, following the TOCTOU and
  no-write-on-mismatch rules. `sg_key_derive_export` is the one place key
  bytes leave the boundary, gated on the `SG_KEY_POLICY_EXPORT_DERIVED`
  policy bit.

- **`sg_verify_mrb`** — envelope in `include/r2p2_mrb_envelope.h` (magic,
  format/scheme, lengths, rollback version, then payload, then a 64-byte
  raw r‖s signature over `SHA-256(domain ‖ header ‖ payload)`);
  micro-ecc `uECC_verify` against a monitor-compiled public key
  (`mrb_pubkey.h`); rollback cap check *before* comparison so a hostile
  version can't exhaust the counter; latch on success.

- **Host tooling** — `tools/mrb_sign.rb` (OpenSSL: keygen / pubkey-header
  / sign / verify) and `tools/sg_crypto_test.c` (RFC 8439/4231/5869
  vectors plus a signer↔verifier round-trip, compiled against the real
  monitor sources).

Build integration lives in `monitor/CMakeLists.txt`: the two mbedTLS
files, `platform_util.c`, and vendored `uECC.c` with only secp256r1
enabled and verify-only. The 8 KiB RAM budget is met by tuning
`PICO_STACK_SIZE` (4 KiB — uECC's verify chain measured ~1 KiB via
`-fstack-usage`), a 256-byte libc heap, and compiling out the RAM vector
table and the default alarm pool. The map file confirmed the flash
veneers stayed RAM-resident and `.gnu.sgstubs` stayed at its fixed
address. **Decisions recorded here** (all settled with the maintainer):
ECDSA-P256 via micro-ecc, rollback flag-gated, chip-ID dev fallback.

---

## Part II — Proving it on hardware

The self-test is the bridge from "22/22 host vectors pass" to "the NS→S
boundary computes the same thing on real silicon."

### `7b2661d7` — on-target veneer self-test (`TZ.selftest`)

`tz/ns/tz_selftest.c` exercises every phase-2 veneer from Non-secure and
prints one line per check over USB CDC: keystore open/policy/derive/close,
stale-handle rejection, handle-table exhaustion, `derive_export`
determinism and length limits, HMAC determinism, an AEAD round-trip with
tamper and wrong-AAD rejection (asserting the output is *untouched* on tag
mismatch, on hardware), and the full `sg_verify_mrb` success / latch /
rollback / tamper matrix against dev-signed packages embedded via a new
`mrb_sign.rb selftest-header` subcommand. Registered from
`ports/rp2040/main.c` because the R2P2 gem has no C `gem_init`; it is an
irb method because USB CDC only comes up once the scheduler runs.

### `ca1ca3c8` — call `mrb_hal_write` directly

First link of the self-test failed: `picorb_hal_write` is a *per-VM macro
alias* (`#define`d to `mrb_hal_write` for the mruby build), not a symbol,
so referencing it produced an undefined reference and an ARM/Thumb
relocation error. Fixed by naming the real symbol. A small commit but a
genuine trap for anyone writing C against the machine HAL.

### `3ddc45e6` — README: 39/39 on hardware

`TZ.selftest` returns `RESULT: PASSED` (39 checks) on board 1 from a fresh
boot — the pre-latch GATEWAY_PSK gate check only runs before the first
`verify_mrb`, so a fresh boot is required for full coverage.

---

## Part III — The Ruby surface

Three commits of API and — the bulk of the effort — three of build
integration, because adding the mbedTLS gem to a TrustZone build fought
the CMake source selection.

### `e64528b0` — `Digest::SHA256`, `TZ.derive_key`, `TZ.verify_mrb`

`tz/ns/tz_api.c` is the intended consumer path made real:
`Digest::SHA256.digest/hexdigest` over `sg_sha256` (one-shot only, by
decision — the hardware engine holds state under an exclusive bootrom lock,
so a streaming API would let NS pin a Secure resource); `TZ.derive_key`
wrapping `sg_key_derive_export` to hand NS a session key for
`MbedTLS::Cipher#key=`; `TZ.verify_mrb` returning true/false. Registration
consolidated into one `mrb_tz_api_init`. The commit also adds
picoruby-mbedtls to the pico2 build config (the NS session-crypto
consumer) and a committed **dev** secp256k1 boot key (authenticates
nothing — see Part V).

### `75e67436` — keep picoruby-mbedtls ports in non-WiFi builds

The R2P2 CMake had been *excluding* `picoruby-mbedtls/ports/**` in the
non-WiFi branch (it was assumed WiFi-only). With the gem now in the
config, its `src/*.c` in `libmruby.a` reference the `MbedTLS_*` port
symbols, so the ports must link — and must see the *same*
`MBEDTLS_CONFIG_FILE` the gem's rake-side objects used, or the context
structs are sized differently. Fixed by adding the config define and
removing the ports from the exclusion glob.

### `dea0c911` — include the entropy glue

Next link error: `mbedtls_hardware_poll` undefined. mbedTLS's entropy
module needs it, and it lives in the SDK's `pico_mbedtls.c` (previously
WiFi-only). Under TrustZone its `get_rand_64()` is already `--wrap`ed onto
`sg_random_bytes` by phase 1's `rand_ns.c`, so pulling the one file in
gives NS-side mbedTLS Secure-TRNG-backed entropy for free.

### `977a3ec4` — fix the picotool seal invocation

The `rake r2p2:tz:package` signing path had never actually run; its
`picotool seal --sig <key> in in` was a guess. The real CLI is
`picotool seal --sign <in> <out> <key> [otp.json]`, and it usefully emits
the BOOTKEY fingerprint JSON as a side effect. (Lesson, twice-learned this
phase: verify a tool's CLI before scripting it.)

### `23385534` — README: sealed path + Ruby surface verified

On target: the sealed-monitor path boots, and an AES-256-GCM round-trip
keyed by `TZ.derive_key` completes in irb — the tier-2 model working end
to end from the Ruby prompt.

---

## Part IV — Probe-first diagnostics (hand-off item 0)

With the Debug Probe in hand, the phase-1 LED "morse code" is retired for
a real post-mortem channel.

### `bdd5de5f` — the `tz_diag` record; strip the scaffolding

`monitor/tz_diag.h` defines a record pinned by the linker to `0x20080000`
(a linker `ASSERT` guards the address, since it's part of the debug
contract). `main.c` stamps `boot_stage` through the boot, and every Secure
fault handler now fills the record — IPSR fault kind, stacked NS PC/LR/xPSR,
MSP_NS, and CFSR/HFSR/BFAR/SFSR/SFAR — then parks in `wfi` for the probe.
The LED breadcrumb/read-out survives behind `-DR2P2_TZ_LED_DIAG` (default
ON for the non-W board that *has* an LED; OFF for the Pico 2 W, whose
GPIO25 is the CYW43 chip select, and for production). On the NS side:
`ns_trap.c` and its five `--wrap` lines are deleted, `exit_ns.c` becomes a
one-shot CDC report then `bkpt` (probe halts with a backtrace; unattended
it escalates to the monitor's fault handler and lands in `tz_diag`), and
`ports/rp2040/main.c`'s blink table becomes a console message. New crib
sheet `tools/PROBE.md` and gdb helper `tools/tz_diag.gdb`. No UART
anywhere — SWD only.

### `fdcfc312` — `flash_ns` trap without `ns_trap.c`

Removing `ns_trap.c` broke the NS link: `flash_ns.c` had a hidden
`ns_trap_code` consumer (a failed Secure flash veneer is an invariant
break worth trapping). Rewritten to park the failing op and rc in globals
and `bkpt` — same probe/`tz_diag` post-mortem, no shared shim. A reminder
that `--wrap` consumers can hide in unrelated files.

### `6d8659ba` — README: item 0 verified on Pico 2 W

The `tz_diag` record read cleanly over SWD (`boot_stage=5`, no fault), the
probe flashed both ELFs without BOOTSEL, and `TZ.selftest` passed on the
2 W — confirming the record-only diagnostics flavor.

---

## Part V — Secure boot

The one part where "just run it" is the wrong instinct. Structured so
everything before the enable is reversible and provable.

### `6db133f3` — rehearsal + gated recipe (no burn)

A fresh secp256k1 key generated **off-repo** (`~/.r2p2-tz-keys/`, never
committed — the committed dev key authenticates nothing). The monitor is
re-sealed with it, and the real-signed combined image is proven to boot
*repeatedly on board 1 with secure boot still OFF* — the reversible gate:
a sealed image boots fine on a non-secure-boot board, so this exercises
the whole signature chain without committing. `tools/OTP-BURN.md` is the
gated recipe: A provision keys 48/49, B burn BOOTKEY, C
`SECURE_BOOT_ENABLE`, each with exact `picotool` selectors and
stop-and-verify gates. Nothing burned.

### `5050a9b0` — group A burned (keys → pages 48/49)

The first irreversible write, on board 1 (chip ID confirmed `561F…` via an
OTP read, distinguishing it from board 2, which also is a non-W Pico 2 but
has a burned BOOTKEY). Method: capture a baseline `TZ.derive_key`
fingerprint (dev fallback) → `picotool otp load -e -s 0xc00 device_root.bin`
and `-s 0xc40 gateway_psk.bin` → reboot → the fingerprint *changed*
(`5cb3fde3…`→`eea589c8…`), proving the keystore switched off chip-ID
fallback to OTP keys; `TZ.selftest` still passed. Non-bricking. A permanent
consequence recorded in the burn log: board 1's GATEWAY_PSK is a random
*placeholder* and can never be rewritten.

### `dff6ab42` — secure boot ENABLED; recipe corrected

The point of no return — and a surprise. The plan treated B (burn BOOTKEY,
non-bricking) and C (`SECURE_BOOT_ENABLE`, bricking) as separate steps.
But **`picotool seal --sign` writes `crit1: { secure_boot_enable: 1 }`
into `bootkey_otp.json`**, so `picotool otp load bootkey_otp.json`
performed B *and* C in one write. Caught immediately in the command echo
(`crit1: secure_boot_enable: 0x00000001`) and confirmed by reading CRIT1
back as `1`. It was survivable because the pre-flight was already done:
the freshly re-flashed image reported `signature: verified`, and the
BOOTKEY fingerprint was the SHA-256 of that same verified image's key — so
when enforcement turned on, the ROM had a valid signature to check. The
board rebooted under enforcement in ~2 s and `TZ.selftest` passed. Debug
was left enabled (`DEBUG_DISABLE=0`), so SWD survives. The commit corrects
`OTP-BURN.md`: the JSON load *is* the point of no return; a true B-then-C
split requires stripping `crit1` from the JSON first.

### `720dee18` — README: phase 2 complete

Board 1 boots only the `boot_signing.pem`-sealed image under mask-ROM
enforcement. Phase 2's four hand-off items are done; what remains is
backlog (`sg_launch_core1_ns`, `sg_deep_sleep`, secure-stack sealing).

---

## Hard-won facts — phase 2 additions

Complementing phase 1's list; these were paid for on hardware this phase.

1. **`picotool seal --sign` bundles `secure_boot_enable`.** Loading the
   emitted `bootkey_otp.json` enables secure boot, not just the BOOTKEY.
   Strip the `crit1` key for a separable burn. (`dff6ab42`.)
2. **A running R2P2 (TZ) exposes no picoboot interface**, so `picotool`
   OTP writes and `picotool reboot -f -u` need the physical BOOTSEL
   button — there is no software path to BOOTSEL (only `bootsel_pressed?`
   reads it). Plan OTP sessions to minimize button presses.
3. **`picorb_hal_write` is a macro alias, not a symbol** — C code linking
   against the machine HAL under mruby must call `mrb_hal_write`.
   (`ca1ca3c8`.)
4. **Adding an mbedTLS-consuming gem to a TZ build** requires: the gem in
   the build config, its `ports/**` kept in the non-WiFi CMake glob with
   the matching `MBEDTLS_CONFIG_FILE`, and `pico_mbedtls.c` for
   `mbedtls_hardware_poll`. (`75e67436`, `dea0c911`.)
5. **The OTP byte order round-trips**: `picotool otp load -e` writes
   little-endian 2-bytes/row and `keystore.c` reconstructs the same, so a
   provisioned 32-byte secret reads back byte-for-byte (verified against
   the row dump).
6. **With the probe attached, `/dev/ttyACM0` is the probe's own UART** —
   the Pico's console is usually `ttyACM1`; resolve via
   `/dev/serial/by-id`. And on first connect the R2P2 shell eats the boot
   banner as input, so drain the port and send a bare CR before typing.
7. **Board identity from OTP**: rows 0x00–0x03 low halfwords are the chip
   ID; reading them distinguishes otherwise-identical boards before an
   irreversible write. Board 1 = `561F0E08F528C156`.
