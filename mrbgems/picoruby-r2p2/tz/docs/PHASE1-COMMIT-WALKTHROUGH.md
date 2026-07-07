# Phase 1 commit walkthrough — TrustZone-partitioned R2P2

Written 2026-07-04 for explaining the `trustzone-sketch` branch (43
commits, `5d4ef2ea..aedd1026`, all 2026-07-02/03) to PicoRuby
maintainers. It assumes you know PicoRuby's C side well (gems, ports,
the mruby VM) but not hardware bring-up or trusted-execution
environments — the primer below covers exactly the concepts the commits
use, and each commit lists which part of the RP2350 datasheet or
pico-sdk it came from.

The branch splits cleanly into two kinds of commits, and this document
is organized that way:

- **Part I — Implementation** (19 commits): the design, the two-image
  build, packaging, and the fixes that are part of the final system.
- **Part II — Debugging scaffolding** (16 commits): temporary code whose
  only job was to extract one bit of information from a board with no
  working console. Most of it is already removed or marked TEMPORARY;
  none of it is part of the security design. The LED ("morse code")
  protocol is explained here, signal by signal.

A few commits contain both (a real fix plus new scaffolding); those are
listed in Part I with their diagnostic half cross-referenced.

---

## Primer: the five hardware ideas everything below uses

**1. Two worlds on one CPU.** TrustZone-M (Arm v8-M, Cortex-M33) runs
the single CPU in one of two *security states*: Secure (S) and
Non-secure (NS). It is not virtualization and not privilege rings —
both states run the same instruction set on the same core; the
difference is which memory and peripherals the bus will let each state
touch. Our split: a ~22 KiB "monitor" runs Secure; the entire R2P2
firmware (mruby VM, shell, gems, FatFS) runs Non-secure. A compromised
NS runtime can *call* key operations but can never *read* key material.

**2. Who decides what's Secure: IDAU + SAU.** Every address has a
security attribute. The IDAU is a fixed, chip-defined map (RP2350
datasheet §10.2.2): flash (XIP) and SRAM are "Non-secure, divisible",
peripherals are "Exempt" (both worlds may address them — filtering
happens elsewhere, see ACCESSCTRL). The SAU is a small programmable
region table (8 regions) the monitor sets at boot to carve the divisible
ranges: veneer page S+NSC, NS firmware + filesystem NS, main SRAM NS —
and, crucially, everything *not* covered by an SAU region falls to the
Secure background, which is how the monitor's own flash and RAM are
protected without spending regions on them. An NS access to a Secure
address doesn't return garbage — it raises a **SecureFault/BusFault**,
a CPU exception. "The board faulted at address X" is the hardware
equivalent of a NoMethodError with a backtrace of exactly one frame,
and reading out that one frame drove most of Part II.

**3. Peripherals: ACCESSCTRL.** Since peripherals are IDAU-Exempt, a
separate block, ACCESSCTRL (§10.6), holds one register per peripheral
saying who may touch it. Two traps encoded in the commits: writes need a
password (`0xacce` in the upper 16 bits — silently required, bus-fault
if absent), and **reset defaults differ by kind**: memory banks reset
NS-*open* (so the monitor must *revoke* NS from its own SRAM8/9), while
peripherals reset Secure-*only* (so the monitor must explicitly *grant*
the ones NS needs: USB, UARTs, GPIO, DMA channels, timers…). TRNG,
SHA-256, OTP, CLOCKS, POWMAN, XIP control stay Secure-only — that list
*is* the security model.

**4. Crossing the boundary: veneers.** NS code cannot call arbitrary
Secure code. The one legal door is an `SG` (secure gateway) instruction
inside a special S+NSC ("Non-secure callable") memory region. The
toolchain automates this: functions marked
`__attribute__((cmse_nonsecure_entry))` get tiny trampolines ("veneers")
emitted into a `.gnu.sgstubs` section, and the monitor's link produces
an *import library* (`r2p2_sg_implib.o`) holding just the veneer
addresses. The NS image links that object and calls `sg_random_bytes()`
etc. as ordinary C functions. The veneer entry code switches security
state; on return, registers are scrubbed. Everything NS-facing in
`include/r2p2_sg_api.h` follows this pattern. One consequence used
throughout: **the Secure side must treat every NS pointer as hostile**
— each one is validated with the bootrom's `rom_validate_ns_buffer()`
(checks the whole range really is NS) before use.

**5. The bootrom is a participant, not just a bootloader.** RP2350's
mask ROM provides runtime services: signature-verified boot, a
partition table, flash operations that *check the caller's permissions*
(`checked_flash_op`), NS-callable API gateways (each individually
disabled until Secure code opts in), and `rom_validate_ns_buffer`.
Chapter §5.4 documents which ROM APIs exist in which security state —
"this ROM function is Arm-S-only" is the root cause of about a third of
Part II's faults. The bootrom also has private Secure-only RAM,
**BOOTRAM** (0x400e0000), which hosts its locks; "NS touched BOOTRAM"
is another recurring fault signature.

One more software-side mechanism, since it carries half the NS port:
**linker `--wrap`**. `-Wl,--wrap=foo` makes every call to `foo` link
against `__wrap_foo` instead (and `__real_foo` calls the original).
It's how the NS build swaps the SDK's TRNG-backed randomness, flash
driver, and AON timer for veneer-backed replacements *without touching
a single gem* — the same pattern as your MbedTLS wrapper work, but
applied at link time instead of the C API. Caveat learned the hard way
(Part II): `--wrap` can't intercept a call the compiler already inlined
within the same translation unit.

### Reference index

| Source | Used for |
|---|---|
| Datasheet §10.2.2 | IDAU fixed map; SAU background; bootrom's reserved SAU region 7 |
| Datasheet §10.5 | Secure-boot OTP procedure (referenced, not executed in phase 1) |
| Datasheet §10.6 (esp. §10.6.2.2) | ACCESSCTRL password/defaults; RESETS dual-gate; "BOOTRAM is hardwired Secure-only" |
| Datasheet §5.1.14 | Partition-table-in-image boot |
| Datasheet §5.4 (esp. §5.4.8) | Bootrom API security levels; `bootrom_state_reset` is Arm-S-only; `flash_op` is NS-callable |
| Datasheet §5.9 | `rp2350_arm_ns` images are "not directly bootable" → monitor performs NS entry |
| pico-bootrom-rp2350 sources | Confirmed SAU-at-exit state, `rom_validate_ns_buffer` semantics, CFLASH flag layout (`bootrom_constants.h`) |
| SDK `pico_runtime`/`pico_runtime_init` | Weak per-stage init functions + `PICO_RUNTIME_SKIP_INIT_*` defines — the NS trimming mechanism |
| SDK `pico_rand` | TRNG-reseeded xoroshiro128\*\* — becomes the Secure-side RNG behind `sg_random_bytes` |
| SDK `hardware_flash` | `flash_range_erase/program` are RAM-resident (`__no_inline_not_in_flash_func`) and handle XIP exit/re-enter — reused inside the Secure flash veneers |
| SDK `pico_flash` | `flash_safe_execute` needs the BOOTRAM lock → unusable from NS (deliberately unlinked) |
| SDK `pico_sha256` | Driver for the hardware SHA-256 accelerator (`sg_sha256`, NS-image verify) |
| SDK `pico_bootsel_via_double_reset` | Pre-main constructor that reads POWMAN → had to be unlinked from the NS build |
| GCC CMSE docs / `-mcmse` | `cmse_nonsecure_entry`, `--cmse-implib`, register-args-only ABI, `.gnu.sgstubs` |
| TinyUSB | `tud_task()` non-reentrancy (empirical; consistent with TinyUSB's single-context contract) |

---

## Part I — Implementation commits

### Stage A: design on paper (before anything compiled)

**`5d4ef2ea` — Add TrustZone S/NS partition sketch**
The contract-first commit: the full veneer API header
(`r2p2_sg_api.h` — key handles, TRNG randomness, one-shot SHA-256,
HKDF/AEAD/HMAC, `sg_verify_mrb`), both linker scripts, and the README
with the memory map. Two decisions here shape everything after:
(a) the monitor gets flash 0x10000000–0x1000FFFF with the veneer page
pinned at 0x1000F000, NS gets the rest, and the FAT filesystem keeps
its existing 0x340000 offset so on-flash layout is unchanged; (b) the
monitor's RAM is SRAM8+SRAM9 (2×4 KiB scratch banks) because RP2350's
main 512 KiB SRAM is *word-striped* across banks 0–7 — per-bank
ACCESSCTRL gating cannot carve a contiguous Secure region out of it, so
the VM heap doesn't shrink by a single byte. *Sources: datasheet
address map (striped vs direct-mapped SRAM), Arm TrustZone-M docs.*

**`f600be4f` — monitor skeleton; reconcile design with verified facts**
The first draft guessed; this commit re-derived the plan from datasheet
§10.2.2/§10.6/§5.4 and the bootrom sources, and wrote `monitor/main.c`
against real SDK register names. Corrections that mattered: peripherals
and SIO are IDAU-Exempt, so the sketch's SAU regions for them were
meaningless and were dropped (ACCESSCTRL is the only filter there); the
bootrom exits with the SAU already on and region 7 claimed; ACCESSCTRL's
password/reset-default semantics; and — from §5.9 — the bootrom
*cannot boot an NS image*, so the monitor must perform the NS entry
itself (`VTOR_NS`/`MSP_NS` setup, then `blxns`). Phase-1 policy
decisions were recorded here too: monitor executes from flash (XIP)
because the threat model is a compromised NS runtime, not a physical
flash-swap attacker; AEAD will be ChaCha20-Poly1305 (no AES hardware on
RP2350, constant-time in software); `sg_verify_mrb` deferred to phase 2.

**`07dbfab1` — NS runtime-init trimming + S/NS contract header**
The stock SDK boot sequence assumes it owns the whole chip; Non-secure,
several of its stages would fault or hang. This commit audits *every*
runtime-init stage (the README has the full disposition table) and
handles the incompatible ones through the SDK's own extension points —
`PICO_RUNTIME_SKIP_INIT_*` defines and strong overrides of weak stage
functions (`ns/runtime_init_ns.c`): bootrom state reset is an
Arm-S-only ROM API (§5.4.8) → skipped; the RESETS-mask stages would
wait forever on Secure-only reset bits → overridden; CLOCKS is not even
*readable* from NS → overridden to report contract frequencies via
`clock_set_reported_hz()` so `clock_get_hz()` consumers (UART baud,
I2C/SPI timing, TinyUSB) keep working. `r2p2_tz_config.h` is born as
the shared S/NS contract (memory map, promised clock frequencies).
Also from the datasheet's coprocessor map: the monitor must grant NS
access to CP0 (RP2350's GPIO coprocessor) and CP4 (double-precision
coprocessor) via NSACR, or the VM's first Float operation traps.

### Stage B: the veneers, and making two images actually build

**`d94ed93d` — route all NS randomness through `sg_random_bytes`**
First real veneer. Secure side: validate the NS buffer
(`rom_validate_ns_buffer`, RCP-hardened booleans per the bootrom docs),
fill it from Secure `pico_rand` — the TRNG stays Secure-only forever,
and pico_rand's TRNG-reseeded xoroshiro amortizes TRNG latency inside
the monitor. `sg_sha256` (hardware accelerator via `pico_sha256`,
CPU-fed) lands here too. NS side (`ns/rand_ns.c`): everything random in
the whole stack already funnels through the SDK's `get_rand_*()` —
picoruby-rng, mbedTLS's `mbedtls_hardware_poll`, lwIP — so replacing
that one API fixes every consumer with **zero gem edits**. This is the
port's central trick and it repeats for flash and the AON timer.

**`d9a83b8e` — NS flash HAL substitution + monitor CMakeLists**
Same trick for flash: FatFS/littlefs keep calling
`flash_range_erase/program`; the NS build substitutes implementations
(at this point, calling the bootrom's `checked_flash_op`, which is
NS-callable per §5.4.8.9 and validates the range against partition
permissions — later replaced, see `b87d656e`). One genuinely new
veneer: `sg_flash_flush_cache()`, because the ROM op does no XIP-cache
maintenance, the ROM's own flush is Arm-S-only, and letting NS write
the XIP maintenance window (`XIP_CTRL.MAINT_NONSEC`) is unsafe while
Secure code executes cached XIP. Also adds the monitor's standalone
CMake project: minimal trusted-computing-base link set, `-mcmse`,
`--cmse-implib/--out-implib` emission of the veneer import library.

**`163330ff` — fix veneer ABI + linker script issues (monitor now links)**
Three compiler/linker realities surfaced by the first real build,
worth knowing before reviewing the header: (1) `cmse_nonsecure_entry`
functions can only take *register* arguments — the NS stack is
untrusted, so GCC refuses stack-passed args; the 9-argument AEAD calls
became request structs (`sg_aead_op_t`), with the TOCTOU rule
documented (copy the struct Secure-side before validating its embedded
pointers, never re-read NS memory after validation). (2) GCC's IPA
optimizer clones functions into local `*.constprop` symbols, which CMSE
veneer generation rejects — hence `SG_API` carries `noipa, used`.
(3) Linker-script bookkeeping: `.gnu.sgstubs` placement broke LMA
monotonicity, and crt0 unconditionally expects scratch-bank copy-table
symbols. Verified result: 13 veneers at exactly 0x1000F000, implib
exporting all 13, monitor ~21.5 KiB flash / ~7.3 KiB of 8 KiB RAM.

**`717ee41b` — wire up the NS R2P2 build (compiles and links)**
Threads `R2P2_TRUSTZONE=1` through the rake task and R2P2's CMake, and
applies `ns/ns_build.cmake` (linker script, init trimming, overrides,
implib). The key discovery: the override mechanism had to change.
`pico_rand`/`hardware_flash` are SDK INTERFACE libraries whose .c files
compile as *peer objects* of the executable — redefining their symbols
is a multiple-definition error, so the port switched to linker
`--wrap` (SDK-idiomatic; it uses `--wrap` itself for AEABI float
routines). Bonus: the wrapped Secure-only originals become unreferenced
and `--gc-sections` deletes the TRNG/QSPI code from the NS image
entirely — verified by symbol inspection. Also recorded: psg and
pitchdetector *cannot* be dropped at the R2P2-CMake level because their
Ruby-binding `src/*.c` inside libmruby.a references the port symbols;
they compile and their core-1 launch faults at runtime until phase 2's
`sg_launch_core1_ns`.

### Stage C: packaging — making two images one trustable artifact

**`751939e2` — ship-together packaging: NS hash manifest in the monitor**
How does the *Secure* image know the *NS* image is the one it shipped
with? Decision (revising the earlier "one signed unit" idea): the
bootrom verifies only the monitor's signature; the monitor holds a
SHA-256 digest of the NS image in a dedicated `.ns_manifest` section
and checks it at boot (`verify_ns_image()`, on the already-linked
`pico_sha256`; mismatch parks the core, BOOTSEL recovery unaffected).
The `rake r2p2:tz:package` task computes the digest, patches it in with
`objcopy --update-section`, seals with picotool *after* patching (so a
signature transitively covers the NS bytes), and concatenates both UF2s
into one `R2P2-TZ-combined.uf2` (UF2 blocks are self-addressing — one
BOOTSEL drop flashes both images). Dev ergonomics preserved: an
unpatched placeholder manifest skips the check, so plain cmake builds
stay bootable. Verified by comparing the embedded digest against an
independent `sha256sum` of the NS binary.

**`789bf5db` — embed the flash partition table in the monitor**
`monitor/r2p2_tz_pt.json`, embedded via `pico_embed_pt_in_binary`
(partition-table-in-image boot, §5.1.14). Two partitions: `firmware`
(0–0x340000, NS permissions *empty* — the bootrom's `checked_flash_op`
rejects any NS write here, which is what makes "NS cannot reflash the
monitor or itself" an enforced property instead of an assertion) and
`fs` (0x340000–end, NS read/write). The table rides in the boot image
and becomes the resident table the bootrom validates flash ops against.

### Stage D: on-target fixes (found by the Part II diagnostics, but
### permanent parts of the system)

First flash of the combined image happened here; the board is a Pico 2
with **no SWD probe and no working USB yet**, so every root cause below
was read out over the LED — Part II describes how. This sequence is,
in effect, an empirical census of "what does stock SDK + R2P2 code
touch before main() that Non-secure code may not touch".

**`1c00f358` — NS may not touch RESETS (first NS instruction hang)**
The monitor completed and `blxns`ed, but NS died before `main()`: the
overridden early-resets stage still called `reset_block_mask()`, and the
RESETS peripheral resets to Secure-only. Fix: the NS reset stages become
no-ops — the monitor already brought every peripheral out of reset
before handoff. (RESETS can reset OTP/TRNG/SHA-256/XIP, so it can't be
blanket-granted; see `06801fe6` for the refined grant.)

**`90d1b432` — NS may not touch BOOTRAM, part 1 (bootrom lock)**
BusFault at 0x400e0000 = BOOTRAM, the bootrom's Secure-only private RAM
(§10.6.2.2 says hardwired). Two NS paths reached it: the
`bootrom_locking_enable` init stage (skipped via define — the monitor
already enabled bootrom locking system-wide, and NS ROM calls lock
Secure-side inside the gateways) and `pico_flash`'s
`flash_safe_execute` path (NS flash code rewritten to call the ROM
gateway directly; `pico_flash` unlinked). Verified by checking the NS
ELF for zero references to 0x400e0000.

**`e61669d2` — NS may not touch BOOTRAM, part 2 (boot locks)**
Next boot, next fault: `runtime_init_boot_locks_reset` writes the
hardware boot locks, also in BOOTRAM. Skipped via define. Importantly,
this commit *enumerated every remaining runtime-init stage* and
established that only two touched BOOTRAM — turning the fix from
whack-a-mole into a closed audit.

**`b5256f5a` — NS may not touch POWMAN (double-tap ctor, AON clock)**
Two POWMAN faults: `pico_bootsel_via_double_reset` has an
`__attribute__((constructor))` that reads `powman_hw->chip_reset`
*before main* — unlinked from the TZ build (BOOTSEL still reachable via
the button); and `Machine.set_hwclock` → `aon_timer_*`, whose backend
is POWMAN — replaced by `ns/aon_ns.c`, a software wall clock on TIMER0
(NS-granted) behind four `--wrap`s. The commit also scanned *all* SDK
constructors for other Secure-hardware touchers (none found), same
closed-audit discipline.

**`06801fe6` — grant NS the RESETS block (peripheral drivers init again)**
`uart_init` faulted: every SDK peripheral driver reset-cycles its block
via RESETS on init. Datasheet §10.6.2.2 resolves the apparent conflict
with `1c00f358`: an NS reset of peripheral X requires the RESETS
*block* grant AND peripheral X's own grant — each reset bit is
individually gated. So granting RESETS to NS is safe: NS still cannot
reset OTP/XIP/CLOCKS, because those peripherals themselves are
Secure-only. This is the subtlest ACCESSCTRL fact in the port.

**`cdd66139` — machine.c: skip Secure-only CLOCKS writes in
`picorb_hal_init`** — the only *gem* source change of the whole boot
sequence (guarded by `#ifdef R2P2_TRUSTZONE`): the `sleep_en0/1` writes
before `tud_init` only tune idle clock-gating; NS keeps the defaults
and the monitor owns CLOCKS. This unblocked USB initialization.

**The USB triad — `dc849b8a`, `d790e0e0`, `7b902b72`: `tud_task()` is
not reentrant.** The single most important *software* lesson of the
bring-up, and the one most likely to bite future maintainers. R2P2
services TinyUSB from `usb_irq_handler` (USBCTRL_IRQ, routed to NS via
NVIC ITNS by the monitor). During bring-up, `tud_task()` was ALSO being
called from a scheduler idle poll (a bring-up workaround, `561a0c05`),
from the keepalive/halt loops, and — pre-existing stock behavior — from
`picorb_hal_getchar`. Each combination corrupted the USB device state a
different way: enumerates but bulk endpoints NAK forever (host reads
hang in uninterruptible I/O); drops off the bus the instant the host
opens the port; shell shows nothing and ignores input. The fixes,
respectively: service USB from the IRQ only (`dc849b8a`, which also
removed the idle poll); any halt-state loop that must pump USB itself
first disables USBCTRL_IRQ so exactly one context owns `tud_task`
(`d790e0e0`); and `getchar`'s `tud_task()` call is compiled out under
`R2P2_TRUSTZONE` — the IRQ's `tud_cdc_rx_cb` fills `stdin_rb` and
getchar just reads it (`7b902b72`). Rule going forward: under TZ,
exactly one context may ever call `tud_task()`.

**`5797c0b2` — set the SECLEVEL field in `checked_flash_op` flags**
The FS format at boot failed with bootrom error -5 (INVALID_ARG). From
`bootrom_constants.h` (pico-sdk): the CFLASH flags word has a SECLEVEL
bitfield (bits 9:8) that must be 1 (SECURE), 2 (NONSECURE) or 3
(BOOTLOADER) — 0 is invalid and the bootrom rejects the whole call.
The NS wrapper had left it zero. One-line fix; found only because the
LED protocol could blink out a bootrom return code (Part II).

**`106472e4` — mask IRQs across the ROM flash op** *(superseded)* —
correct reasoning (during flash erase/program the flash is unreadable;
an interrupt handler fetched from flash mid-op hangs the core), and the
IRQ mask survives into the final design, but it was insufficient from
NS, because:

**`b87d656e` — move flash erase/program to Secure veneers (final flash
architecture).** On target, the first NS erase hung the core even with
IRQs masked. Root cause: the bootrom's `checked_flash_op` leaves
flash/XIP unreadable *across the call and does not re-enter XIP for the
caller* — so the NS caller's very next instruction fetch (NS runs from
XIP flash!) reads dead flash and locks up. The SDK's normal answer,
`flash_safe_execute`, needs the Secure-only BOOTRAM lock. Conclusion:
**Non-secure code cannot safely perform flash operations on this chip,
period.** The fix promotes erase/program to Secure veneers
`sg_flash_erase/sg_flash_program` that call the SDK's `flash_range_*`
— which are RAM-resident (`__no_inline_not_in_flash_func` places them
in `.data`; crt0's copy table moves them to RAM at boot, verified in
the map file) and handle XIP exit/re-enter and cache flush themselves —
with interrupts masked (in Secure state, PRIMASK_S blocks NS interrupts
too) and the range clamped to the FS partition
`[TZ_FS_OFFSET, TZ_FS_OFFSET+TZ_FS_SIZE)`. Defense in depth: the SAU
already stops NS *reads* of monitor memory, the partition table already
stops NS ROM-mediated *writes* outside `fs`, and now the veneer
re-checks the range anyway. NS-side `flash_ns.c` shrinks to two
`__wrap_` functions calling the veneers.

### Stage E: cleanup and status

**`0e7cf9de` — post-bring-up cleanup** — removes the noisy diagnostics
(idle-loop heartbeat/dot printer), fixes a real bug found in
self-review (`count==0` flash ops now succeed as no-ops like the SDK,
instead of returning an error that would trap the VM), documents the
"program source must not be in XIP flash" constraint, and drops a dead
`--wrap`. The silent-unless-failing LED traps stay until the debug
probe arrives.

**`aedd1026` — README status → phase 1 working on hardware** — records
the verified state and exactly which veneers are field-tested.

---

## Part II — the debugging story, and how to read a firmware bug
## through one LED

### Why an LED at all

Debugging environment for the entire bring-up:

- **No SWD debugger** (the Raspberry Pi Debug Probe was ordered *during*
  this work). No breakpoints, no register dumps, no `addr2line` on a
  live fault.
- **No serial console.** Stock R2P2's console *is* USB CDC — and USB
  was itself broken for most of the bring-up (that's the tud_task
  saga). You cannot print a diagnosis over the channel being diagnosed.
- **No panic output.** `panic()`/`abort()`/failed asserts end in
  `_exit`, whose stock behavior is a `bkpt` instruction — which,
  with no debugger attached, escalates to a HardFault. Externally:
  the board just stops.

What remains is GPIO25, the onboard LED: a 1-bit, human-eyeball-decoded
output channel. Every scaffolding commit below is an answer to the
question *"what is the single most valuable integer I can extract
through one blinking LED, given what I learned from the last flash?"* —
with a human (Ryo) counting blinks on the desk and reporting counts
back per flash cycle. Each flash cycle costs minutes, so each protocol
change also had to maximize information per boot.

### The protocol, as it evolved

Three encodings were used, in increasing order of hard-won readability:

1. **Stage breadcrumbs / heartbeats** — N slow blinks at checkpoint K,
   or continuous blink patterns distinguishing which loop the firmware
   is stuck in. Answers "how far did boot get?" / "which state is the
   VM in?".
2. **Hex nibbles** — 32-bit values (fault addresses, PCs) blinked as 8
   groups of 0–15 blinks. Maximum information, *barely* readable:
   an E nibble is 14 blinks in a row, and in practice long values
   degenerated into an uncountable strobe. Used early, then abandoned
   for anything a human must count reliably.
3. **Marker + small count** — the mature format: an unmistakable ~1.2 s
   long ON pulse (nothing else in the boot does that), then N short,
   well-spaced blinks, long gap, repeat. N stays small (≤ 15) by
   encoding *an index into a table the build already knows* (exception
   class table, fault-path marker) rather than a raw value. When a raw
   value was unavoidable (a return address), it was cut to the minimum
   disambiguating bits first (see `6d055989`). Marker count = which
   trap fired: 2=abort, 3=exit, 4=panic, 5=assert, 6=hard_assert,
   7=flash-erase rc, 8=flash-program rc.

The recurring failure mode of the protocol itself was **ambiguity with
innocent blinking**: the USB interrupt diagnostic toggled the LED at
~1 kHz (a shimmer), enumeration caused irregular flicker, and early
readouts without a start marker were misread as "fast constant blink" —
one misreading sent the investigation down a wrong path for two flash
cycles (`7b902b72`'s message documents the re-interpretation). Hence
the long-pulse start marker and the "unmistakable at a glance" design
rule.

### The commits, in narrative order

**Act 1 — where does boot die? (monitor breadcrumbs and fault
handlers)**

- *(part of `1c00f358`)* **Monitor stage breadcrumbs**: N blinks after
  each Secure boot stage (verify, key stub, partition, handoff = the
  "3+4" pattern seen for the rest of bring-up), plus a distinctive
  strobe in `verify_failed()`. Signal sought: *did the monitor complete
  and hand off, i.e. is the bug Secure-side or NS-side?* Answer: always
  NS-side from here on.
- *(part of `90d1b432`)* **BusFault handler blinks BFAR** (the faulting
  *data address*) as hex nibbles, and SHCSR enables the configurable
  fault handlers so faults arrive classified instead of as one opaque
  HardFault. Signal: *which address did NS illegally touch?* Reading
  0x400e0000 → BOOTRAM identified the bootrom-lock family of bugs.
- *(part of `e61669d2`)* **Switch from BFAR to the stacked NS PC**: the
  fault handler digs the program counter out of the exception frame on
  MSP_NS. Rationale: a data address tells you *what* was touched (and
  BFAR once pointed at ROSC, a dead end); the PC feeds `addr2line` and
  tells you *which line of code* touched it. This one change converted
  faults from riddles into filenames, and localized the boot-locks and
  both POWMAN bugs.
- **`2269e53c` — all fault classes report the PC, HardFault included.**
  A "2-blink loop" turned out to be the HardFault handler's fixed
  count, not a breadcrumb — i.e. the encoding collided with itself.
  Unified: every handler blinks the stacked PC. The PC resolved to
  `_exit`'s `bkpt` — meaning NS *didn't* fault at all; the VM had exited
  deliberately. Everything so far was hardware-boundary bugs; from here
  the bug class changes to "the VM terminates during Ruby boot", which
  is invisible to fault handlers.

**Act 2 — the VM exits during boot: trying to get words out (USB
console attempts, all defeated)**

- **`87cf4e4a` — keepalive console in `main()`**: if `mrb_task_run`
  returns, keep pumping `tud_task()` so CDC enumerates, then print the
  pending exception via `mrb_print_error`. Signal sought: *the actual
  Ruby exception text.* Defeated: the exit happened *inside*
  `mrb_task_run`, so `main()` never regained control.
- **`cb53feab` — strong `_exit` override (`exit_ns.c`) as USB console**:
  catches the C-level `abort()`/`panic()` path that bypasses `main()`.
  Same signal sought, new location — the location the firmware
  actually reaches.
- **`561a0c05` — poll `tud_task()` from the scheduler idle hook**:
  after the aon/clocks fixes the VM ran cleanly but USB never
  enumerated (enumeration is IRQ-driven; the suspicion was that the IRQ
  wasn't reaching NS). Signal: *does polling bring the bus up?* It did
  — but this workaround created the reentrancy corruption that Part I's
  USB triad then had to root-cause. In hindsight: the one diagnostic
  that actively made things worse, and instructive for exactly that
  reason.
- **`944d8edd` — distinct heartbeats per keepalive loop**: FAST blink =
  `main()` keepalive (task scheduler returned), SLOW = `_exit`
  keepalive (C-level abort mid-boot), neither = reached the shell or
  hung. Signal: *which termination path?* — chosen because USB text was
  proving unreliable, so the LED had to carry the state machine.
- **`ee6c055b` — write the diagnosis to CDC unconditionally** (don't
  gate on DTR/`tud_cdc_connected`, just buffer into the FIFO and keep
  flushing). Signal: still the exception text; this removed dependence
  on connection detection, which was broken along with everything else
  CDC. Also defeated (bulk endpoints NAKed — the reentrancy again).

**Act 3 — give up on USB; put the *exception itself* on the LED**

- **`4124d9aa` — blink the exception class name, first 4 chars as 8 hex
  nibbles.** Signal: *which Ruby exception class kills boot?* — the
  right question, in an unreadable encoding.
- **`e8083289` — replace nibbles with a countable index**: a lookup
  table of the 12 plausible exception classes (RuntimeError=2 …
  ScriptError=13, other=15, none=1). This is the moment the protocol
  philosophy flips from "transmit the value" to "transmit an index into
  knowledge both sides already share".
- **`9b1cf1f1` — move the readout into `_exit`**: the "fast constant
  blink" was `_exit`'s own heartbeat — the readout had been sitting in
  `main()`'s keepalive, which never ran. Diagnostic code has the same
  reachability bugs as real code.
- **`4f86cce8` — add the long start-pulse marker**: the counts were
  right but uncountable in the noise. This tiny UX commit made every
  subsequent readout reliable on the first try.

**Act 4 — the answer is "14" (no exception): binary-search the C
termination path**

The readout said: `_exit` with **no pending mruby exception** — a raw
C-level termination, not a Ruby raise. Everything below is a manual,
link-time binary search through "who calls `_exit`?", using `--wrap` as
the probe. (For the mruby-savvy reader: `exc_throw` with `mrb->jmp ==
NULL` prints and `abort()`s, and `mrb->exc` is already cleared by then —
so "no exception at `_exit`" does *not* mean no exception existed.)

- **`49985839` — `--wrap=mrb_print_error`**: blink the class at the
  throw site, before abort clears it. Never fired — later understood
  (`0e7cf9de`): the call was *inlined into `exc_throw`* in the same
  translation unit, and `--wrap` only rewires cross-object references.
  A genuine limitation worth remembering.
- **`77c12ba2` — wrap `mrb_task_run` in `mrb_protect_error`**: catch the
  re-raise at the C boundary and blink its class. Signal: *is this a
  Ruby raise at all?* Answer: **no** — still 14. That negative result
  is what proved the termination was raw C, eliminating the entire
  Ruby-level hypothesis space in one flash. (The protection itself was
  kept in the final tree as a sane top-level handler.)
- **`38346737` — `--wrap` `abort`/`exit`, blink the caller's return
  address** (20 bits, binary; markers 2/3). Signal: *the call site.*
  Static analysis had failed to pin it (candidate sites were compiled
  out or in dead code), so capture it at runtime.
- **`6d055989` — shrink to RA bits [19:8]**: all eight `abort()` call
  sites in the image differ in those 12 bits, so blink 3 nibbles
  instead of 5. Minimum-description-length applied to blinking.
- **`f3e5e570` — also wrap `panic()` and `__assert_func`** (markers
  4/5): abort/exit *never fired* — another decisive negative — so the
  `_exit` entry had to come via the SDK's panic/assert family.
- **`846d19e2` — wrap `hard_assertion_failure`** (marker 6): panic's
  caller was the `hard_assert` funnel; all nine `hard_assert` sites are
  distinct in RA bits [11:0]. The readout ("SLSS SLSL LSLL" from the
  desk) resolved to… `__wrap_flash_range_erase`'s own
  `hard_assert(rc == BOOTROM_OK)`. The killer was the NS flash wrapper
  itself: the FS-format step at boot was failing.
- **`161c79c0` — blink the bootrom return code instead of asserting**
  (markers 7=erase / 8=program, then |rc| short blinks). Signal: *which
  bootrom error?* The desk read "7 + 5" → rc = −5 = INVALID_ARG → the
  SECLEVEL fix (`5797c0b2`). Also halved the monitor breadcrumb timing
  (user request — hardware debugging at 0.5 Hz tests patience).

**Act 5 — the flash op that never returns**

- **`d0d6037a` — idle heartbeat + periodic `.` to stdout**: after the
  SECLEVEL fix, boot went dark with a silent shell. Signal: a 2×2
  decision matrix in one flash — blink + dots = input path broken,
  blink + no dots = output path broken, neither = hung before the
  shell. (Answer: neither → still hanging in boot.)
- **`014e6f51` — LED solid-ON around the ROM flash op**: distinguishes
  *hung inside one flash operation* (LED sticks on) from *many slow
  operations progressing* (flicker). The desk report "solid ON, stuck
  for >2 minutes" was the smoking gun for the XIP-deadlock diagnosis.
- **`dd833395` — re-add the solid-ON alongside the IRQ-mask attempt**
  (`106472e4`): same signal, to test whether IRQ masking fixed the
  hang. It didn't — flash ops moved to Secure veneers (`b87d656e`),
  the LED went dark after "3+4", and the next `tio` session printed an
  `irb>` prompt.

### What's still in the tree

Kept deliberately (all silent unless something fails), to be stripped
once the Debug Probe is in use — see `PHASE2-HANDOFF.md` item 0:
`ns/ns_trap.c` (the five `--wrap` traps + marker protocol),
`exit_ns.c`'s exception-index blink, the protected `mrb_task_run`
readout, and the monitor's breadcrumbs/fault-PC blinker. If a future
board ever boots to a dead LED with no probe attached, this document is
the decoder ring.
