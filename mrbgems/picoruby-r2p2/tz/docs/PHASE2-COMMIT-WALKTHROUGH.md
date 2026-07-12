# Phase 2 commit walkthrough — TrustZone-partitioned R2P2

Written 2026-07-07 for explaining the `trustzone-sketch-2` branch (16
commits, `aedd1026..720dee18`, all 2026-07-07) to PicoRuby maintainers.
**Extended 2026-07-12** with Parts VI–X, covering the phase-2 backlog
burn-down on `trustzone-sketch-3` (11 TZ commits, `9ca065ea..2f68b10f`,
all 2026-07-11).
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
sketch-2 story is organized in five parts, each a coherent chunk:

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

The backlog burn-down (Parts VI–X) closed every item that wasn't
design-gated — 2, 1, 3, 6, 4, 8, in that order (the user-decided
priority, commit `28f170c9`) — all device-verified:

- **Part VI — Trimming the NS VM** (1 commit): item 2 — a TZ build
  config that genuinely removes psg, the one gem that launches core 1
  behind the VM's back.
- **Part VII — Core 1 into Non-secure** (3 commits): item 1 — the
  forced-NS design, its on-device refutation, and the Secure trampoline
  that shipped instead. The veneer reentrancy guards ride along.
- **Part VIII — Deep sleep and the wall clock** (3 commits): item 3 —
  `sg_deep_sleep`/`sg_aon_*`, the nap that killed a USB hub, and the
  wake-path redesign three device bugs forced.
- **Part IX — Absorbing upstream** (2 commits): merging master
  (#451/#454, mruby #6942) back into the TZ tree, and the
  silently-dead-USB interrupt-routing fix the merge surfaced.
- **Part X — Production hardening** (2 commits): items 6, 4, 8 — the
  monitor OTP self-lock, the Secure stack seal, the ACCESSCTRL debug
  lock, and the first fully hardened board.

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

## Interlude — WiFi under TZ (documented elsewhere)

Between the end of sketch-2 and the backlog burn-down sits the
WiFi-under-TZ campaign (`1c50f9cf..a3b1e202`, 2026-07-07/10): the cyw43
bring-up ladder, the busy-VM starvation fix via the mruby task-switch
hook, and the bug-3 NS-heap-corruption hunt. That work produced three
upstream deliverables — picoruby #451 (single-owner USB pump), #454
(SSID verify on connect), and mruby #6942 (task-switch hook API) — and
has its own documents (`WIFI-UNDER-TZ-HANDOFF.md`, `bug3/`). It
re-enters this story in Part IX, when the merged upstream tree comes
back into the TZ branch.

## Primer: the five ideas the backlog adds

**1. Cores cross the boundary individually.** SAU, VTOR, MSP and the
coprocessor grants are all *banked per core* — core 1 wakes up Secure
and knows nothing of core 0's partition. RP2350 also offers a bus-level
big hammer, ACCESSCTRL `FORCE_CORE_NS` (datasheet §10.6.2), which
attributes every access a core makes as NS. Part VII is the story of
trying the big hammer, watching it break the bootrom's own launch
protocol on device, and landing on the architecturally boring answer: a
monitor-resident Secure trampoline that gives core 1 the same
SAU/NSACR/BXNS crossing core 0 got at boot.

**2. The RCP salt is bootrom property.** RP2350's redundancy
coprocessor (RCP) wants a per-core random salt, seeded once by the
bootrom cold path (core 0 writes both cores' salts). It survives PSM
`FRCE_OFF` resets of core 1 — the SDK's relaunch depends on that — and
re-seeding it at runtime while it's already valid stalls the writing
core forever, un-haltable even over SWD. Rule: never touch the salt
outside the bootrom cold path.

**3. Two callers means every veneer needs a lock.** The phase-2 design
assumed a single NS caller (core 0, thread mode, cooperative
scheduler). The moment `sg_launch_core1_ns` exists, that assumption is
dead, so every veneer gets a try-lock at entry that answers
`SG_ERR_BUSY` on contention — a prerequisite of the launch veneer, not
an afterthought.

**4. Deep sleep is a Secure service with a fixed menu.** CLOCKS, PLLs,
XOSC/ROSC and POWMAN are Secure-only, so NS power management is a
veneer offering a closed set of sleep states — never raw register
access. The hard-won half of this idea: a glitchless clock mux pointed
at a source that isn't actually running stalls the clock tree beyond
any software recovery (the core stops mid-instruction, SWD dies), so
the wake path may only step onto *verified* sources.

**5. The monitor can finish its own lockdown.** Some boards ship OTP
page 63 — where the per-page lock rows physically live — already
bootloader-locked, so `picotool` from BOOTSEL can't lock the key pages.
Secure code still can: the monitor burns the page-lock fuses itself at
boot, exactly how real production provisioning works. Together with the
Secure stack seal (Armv8-M recommendation) and the ACCESSCTRL debug
lock, the monitor closes every door phase 2 had left ajar for bring-up.

---

## Part VI — Trimming the NS VM

### `9ca065ea` — drop picoruby-psg from the TZ builds (item 2)

psg's `PSG_tick_start_core1` launches core 1 — a Secure-only bootrom
operation that faults under TZ until item 1 exists — so the gem is cut
from the TZ builds as the quick unblock. The instructive part is that
*config-only removal is not enough*: it takes both halves. A new
`r2p2-picoruby-pico2-tz.rb` build config (stock pico2 minus psg; pico2
no longer shares the stock config under TZ) removes the gem's rake-side
objects, and the R2P2 CMake drops the psg *port* sources — because
`psg_port.c` has a pre-main constructor that claims a SIO spinlock,
which `--gc-sections` dutifully keeps alive. pitchdetector needed
nothing: no build config includes it and its unreferenced port objects
are already gc'd. Verified by `nm`: zero psg / `multicore_launch`
symbols in either prod TZ image. Re-adding psg under TZ is item-1 work
(move its port to `sg_launch_core1_ns` and audit the core-1 loop).

---

## Part VII — Core 1 into Non-secure

The backlog's most expensive item, and the one that best illustrates
the phase's method: a per-datasheet design, an on-device refutation,
and a redesign that survived. Item 1.

### `8c2b6d6d` — first design: forced-NS core 1 + reentrancy guards

The datasheet-suggested route: `partition_configure` pins ACCESSCTRL
`FORCE_CORE_NS.CORE1` before the ACCESSCTRL lock (making it permanent),
so every access core 1 ever makes is NS-attributed and it can never
reach monitor flash/RAM or the veneers. `sg_launch_core1_ns(vtor,
entry, stack_top)` hard-resets core 1 via PSM, then runs the bootrom
mailbox launch protocol; `entry == 0` parks the core (NS has no PSM
access, so park/relaunch also go through the veneer). All waits are
bounded — a wedged core 1 returns `SG_ERR_INTERNAL` rather than hanging
Secure state. The coupled prerequisite ships here too: every veneer
except `sg_version` gets a try-lock (`SG_ERR_BUSY`), bodies moved to
static `*_locked` functions behind uniform entry wrappers. ABI 0x0002.
Honestly flagged in the commit: the forced-NS mailbox path was
per-datasheet but *not yet device-proven*.

### `4f87c09b` — the device verdict: forced-NS launch cannot work

On a pristine-OTP pico2 the launch fails deterministically, and it's a
design bug, not a typo: a forced-NS core 1 bus-errors on the Secure SIO
alias and Secure ROM it runs the bootrom handshake from, and the
bootrom's final `blx` into an NS entry is an illegal S→NS transition
besides. The bounded-wait design was validated *by* the failure — core
0 and the VM stayed fully alive through it. The same session recorded
item 3's first device pass (Part VIII): AON clock and argument
validation PASS, but the dormant nap "inconclusive" behind what looked
like a host USB wedge — correctly re-diagnosed two commits later.

### `bffe0350` — the Secure trampoline (item 1 closed)

The redesign drops `FORCE_CORE_NS` entirely. Core 1 is launched through
the ordinary *Secure* bootrom mailbox into a monitor-resident Secure
trampoline (`core1_ns_trampoline`, main.c) that mirrors core 0's boot
crossing: configure core 1's banked SAU and NSACR/CPACR identically
(shared helpers `tz_sau_configure_ns_regions` /
`tz_grant_ns_coprocessors`), set NS VTOR/MSP_NS, `BXNS` into the
caller's entry. The veneer keeps NS-range/alignment validation and the
deep-sleep gate; every launch starts with a PSM `FRCE_OFF` pulse so
park, relaunch and payload replacement share one path. The commit also
banks the RCP salt lessons (primer §2), including the diagnosis that
the "core 1 stuck at `wait_for_rcp_salt`" state which motivated the
fatal runtime-seeding experiment is an *openocd per-core-reset
artifact* — recover with a full-chip watchdog reboot, never with
openocd `reset`. Device-verified: `TZ.selftest` PASSED twice in one
boot — launch → NS entry runs on core 1 → deep-sleep gated
`NOT_PERMITTED` while core 1 is up → park → relaunch → park.

---

## Part VIII — Deep sleep and the wall clock

Item 3, and the backlog's densest cluster of device-found failure
modes: three bugs, none reachable by reading code, one capable of
taking down the host.

### `4ff86745` — `sg_deep_sleep` + `sg_aon_*` veneers

The fixed-menu design (primer §4): `sg_deep_sleep(mode, arg)` accepts
only `SG_SLEEP_DORMANT_FOR_SECS` for now — new states are new enum
values, the signature never changes. First version runs the pico-extras
dormant recipe Secure-side (clock tree to LPOSC, PLLs deinit, XOSC off,
POWMAN alarm as wake event, `clocks_init()` on wake), with `PRIMASK_S`
held across the teardown so an NS IRQ can't preempt a 32 kHz clock
tree; refuses `NOT_PERMITTED` while core 1 is launched (the monitor
can't quiesce a forced-NS core). `sg_aon_get_ms/set_ms` expose the
Secure POWMAN 1 kHz timer as a real wall clock — started at boot on the
XOSC tick source, left alone if already running, so it persists across
watchdog reboots *and* keeps counting through the nap (tick source
swaps to LPOSC). NS side: `aon_ns.c` rewired off the phase-1 TIMER0
software clock onto the veneers; new `sleep_ns.c` wraps `Machine_sleep`
with a plain-timed-sleep fallback on refusal. ABI 0x0003, 19 veneers in
the implib.

### `a9268e2e` — the nap that killed the hub

`Machine.sleep 3` reproduces on both spare pico2s: CDC never returns,
and the *entire USB hub* the board sits on drops — every sibling device
vanishes, and since this rig's Bus 003 is internal, recovery is a host
reboot. This retro-explains the "host USB wedge" from `4f87c09b` as the
same event. Hypothesis recorded (and later proven): the veneer stops
`clk_usb` with the pull-up still attached mid-transaction, and the
frozen device wedges the hub. Fix direction: detach before sleeping,
and put the debug probe on a different hub than the target.

### `f5708ae2` — three device bugs, a redesigned wake (item 3 closed)

1. **The hub kill** — `sleep_ns.c` now detaches first: flush CDC,
   quiesce `USBCTRL_IRQ` (the only `tud_task` caller under TZ),
   `tud_disconnect()`; reattach and re-enable after wake.
2. **pico-extras' `rosc_enable` idiom** — writing the bare ENABLE field
   mask zeroes `FREQ_RANGE`, which on RP2350 stops the ROSC dead; the
   wake path spun forever at 32 kHz (found by SWD PC-sampling: parked
   in the stable-wait *after* a successful alarm wake).
3. **`clocks_init()`'s clk_ref-via-ROSC step** — its glitchless switch
   onto the not-actually-running ROSC stalls clk_ref/clk_sys outright:
   the core stops mid-instruction, SWD dies entirely, no software
   timeout can ever fire. LED breadcrumbs plus SWD-examinability
   decoded this in one run.

The redesigned recipe removes ROSC from the picture entirely and drops
WFI: clock tree to LPOSC, PLLs/XOSC off, poll the POWMAN alarm flag at
32 kHz (pico-extras' core also spins — same power profile), then
rebuild the boot clock tree strictly via verified sources (XOSC only
after STABLE, PLLs after lock). The design rule this purchased is
primer §4's second half: **never point a glitchless mux at an
unverified source.** Final state, device-verified on board 2:
`Machine.sleep N` naps exactly N seconds repeatably, USB re-enumerates
~1 s after wake, the *same* irb session survives, the wall clock counts
through the nap, host and hub stay healthy.

---

## Part IX — Absorbing upstream

The WiFi campaign's deliverables merged upstream (picoruby #451/#454,
mruby #6942); this part brings them back into the TZ tree — and, as
with every merge this branch has done, the device found what the
compiler couldn't.

### `08dbdd4e` — merge master + adopt the merged hook API

Fifteen master commits in, three conflicts worth recording.
`picorb_hal_getchar` takes master's `usb_pump_request()` — #451's
single-owner pump supersedes the TZ-guarded direct `tud_task()`, and
its single-owner rule holds under TZ because the pump worker runs on a
claimed user IRQ. `cyw43.c` keeps the TZ branch's
`cyw43_init_last_error` recording on top of the merged #454. And the
mruby submodule needs *neither side alone*: it bumps to the upstream
master containing the merged #6942 task-switch hook, whose final API
grew a `mrb_task_switch_reason` discriminator — so the merge also
updates the HAL ports. The rp2040 pump hook deliberately does *not*
branch on the reason: TASK and GC_STEP switches both starve the network
stack.

### `8ae279cf` — route user IRQs to NS (merged tree device-verified)

Two fixes the merge surfaced on device. Small: the R2P2 CMake compiles
the rp2040 port directly rather than as an mrbgem, so `hal.h`'s new
`task_hal.h` include needs mruby-task's include dir on the target path.
Load-bearing: #451's pump claims a software user IRQ (`SPAREIRQ_*`) as
its deferred-work vector, and those IRQs were not in the monitor's ITNS
list — NS writes to their NVIC enable/pend bits were silently RAZ/WI,
the pump never fired, `tud_task` never ran, and USB never enumerated.
All six user IRQs are now routed NS. Device-verified on the merged
image: USB enumerates, `TZ.selftest` PASSED including the full core-1
cycle, `Machine.sleep 3` naps with re-enumeration and the AON clock
advancing.

---

## Part X — Production hardening

Items 6, 4 and 8 — the monitor-side complements to Part V's OTP burns,
ending with a board that is hardened all the way down.

### `5cec5166` — monitor self-lock for key-page provisioning (item 6 P2)

The `OTP-BURN.md` production recipe's P2 step (lock the key pages:
Secure read-only, NS/bootloader no-access) assumed `picotool otp set
PAGEnn_LOCK…` from BOOTSEL. On the SparkFun Pro Micro RP2350 that
returns "permission failure": the board ships OTP **page 63 — where the
`PAGEnn_LOCK` rows for pages 48–63 physically live — pre-locked
bootloader-read-only** (`LOCK_BL=1`). But page 63's `LOCK_S=0` leaves
Secure code able to write, which is how real production provisioning
does it anyway. So `ks_provision_locks()`: at boot the monitor advances
the fuse locks on provisioned key pages (Secure read-only, NS/BL
no-access) and the rollback page (NS/BL only — the monitor still writes
the counter), gated two independent ways — compile-time `R2P2_TZ_PROVISION_LOCKS`
(default OFF; a dev image carries no fuse-burning code) and a runtime
check that locks only genuinely key-provisioned pages
(`dev_fallback==false`), never a blank one. Idempotent
(thermometer-coded locks), and ordered *before* the SW_LOCK ratchet so
the key reads and blank checks happen while the pages are still
readable. `OTP-BURN.md` P2 now documents method A (picotool) vs method
B (self-lock) with the board-class caveat.

Device-verified on the SparkFun spare (`8AA23037959E1B47`): after the
burn, `PAGE48/49_LOCK1 = S=ro / NS=none / BL=none`, blank page 50
correctly skipped, `TZ.selftest` PASSED with derive fingerprints
unchanged, and `picotool otp dump` of the key rows refused where it
had been readable pre-burn. The same session then executed the *rest*
of the production recipe — P3 glitch detectors, P4 BOOTKEY + secure
boot, P5 debug disable — recorded in the `OTP-BURN.md` burn log rather
than as commits (execution, not code). End state: the SparkFun board is
the project's first fully hardened device — mask-ROM signature
enforcement, key pages fused shut, glitch detectors armed, SWD
permanently dead, USB CDC and signed-BOOTSEL-load the only ways in.

### `2f68b10f` — Secure stack seal (item 4) + debug lock (item 8)

Two small monitor changes that close the remaining bring-up-era doors.
The stack seal (Armv8-M recommendation): `memmap_monitor_s.ld` reserves
the top 8 bytes of RAM_S as `__StackSeal` with `__StackTop` (crt0's
initial SP) below it, and `tz_seal_secure_stack()` writes the two
`0xfef5eda5` words at boot, before anything Non-secure runs — a return
that unstacks from the empty Secure stack now faults on the seal. Done
in C at boot rather than a crt0 fork so the seal stays inside the
signed image; verified on the sealed SparkFun board under secure-boot
enforcement. The debug lock: `partition_configure` sets
`ACCESSCTRL_LOCK_DEBUG_BITS` when built `-DR2P2_TZ_LOCK_DEBUG=ON`,
denying an attached debugger the ACCESSCTRL security override. Default
OFF — it would break the probe/`tz_diag` workflow, and it is
deliberately independent of the OTP debug fuses, so a board can be
OTP-provisioned while keeping SWD for diagnosis (exactly the bring-up
sequence the SparkFun board itself followed). Pair with `OTP-BURN.md`
P5 for production.

---

## Where this leaves the branch

Every hand-off item and every non-design-gated backlog item is closed
and device-verified. Still open, deliberately: **items 5 and 7**
(separate signed application image; `--in-implib` veneer-address
stability) are blocked on a security-model rethink and only matter once
NS updates decouple from the monitor — and **item 9**, the slightly
off-center boot logo, which waits for the branch to be mergeable. The
reusable deliverable beyond R2P2 itself is the monitor self-lock
pattern: Secure-side OTP provisioning locks for board classes where the
bootloader path is fused shut.

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

### Backlog additions (2026-07-11)

8. **Never write the RCP salt outside the bootrom cold path.** It
   survives PSM `FRCE_OFF` (relaunch needs no seeding), and re-seeding
   a valid salt stalls the writing core forever, un-haltable over SWD —
   only bus-AP memory reads still work. (`bffe0350`.)
9. **openocd per-core resets strand core 1 salt-less** (core 0's seed-skip
   leaves it at `wait_for_rcp_salt`). After `program … reset exit`, always
   full-chip watchdog-reboot before exercising the core-1 launch; openocd
   `reset` recreates the artifact. (`bffe0350`.)
10. **`FORCE_CORE_NS` is incompatible with the bootrom mailbox launch**:
    a forced-NS core bus-errors on the Secure SIO/ROM handshake, and the
    bootrom's final `blx` into an NS address is an illegal S→NS
    transition. Launch Secure, cross via a trampoline. (`4f87c09b`.)
11. **Detach USB before stopping `clk_usb`.** A device frozen
    mid-transaction with its pull-up attached takes down the entire hub —
    on a rig with an internal hub, that's a host reboot. `tud_disconnect()`
    first, reattach after wake. (`a9268e2e`, `f5708ae2`.)
12. **Never point a glitchless clock mux at an unverified source** — the
    stall is beyond any software bound (core stops mid-instruction, SWD
    dies). Corollary: pico-extras' `rosc_enable` idiom zeroes
    `FREQ_RANGE` on RP2350 and stops the ROSC dead. (`f5708ae2`.)
13. **User IRQs (`SPAREIRQ_*`) must be in the monitor's ITNS list** or NS
    writes to their NVIC bits are silently RAZ/WI — #451's USB pump never
    fires and enumeration just doesn't happen, with no fault to see.
    (`8ae279cf`.)
14. **Some boards fuse OTP page 63 bootloader-read-only at the factory**
    (SparkFun Pro Micro RP2350), so `picotool` can't write the
    `PAGEnn_LOCK` rows from BOOTSEL. Secure code still can (`LOCK_S=0`) —
    the monitor self-lock is the production-shaped answer. (`5cec5166`.)
