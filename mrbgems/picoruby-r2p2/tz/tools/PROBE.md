# Debug Probe crib sheet (Pico 2 W, TZ build)

Wiring: Debug Probe **D port** → the Pico 2 W's 3-pin JST-SH debug socket
(SWD). The **U port (UART) is not used** — the monitor has no UART by
design and NS console output rides USB CDC; post-mortem goes through the
`tz_diag` record instead.

## Attach

```sh
openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c "adapter speed 5000"
# other terminal:
gdb-multiarch mrbgems/picoruby-r2p2/tz/monitor/build/r2p2_tz_monitor.elf \
    -ex "target extended-remote :3333"
```

Debug is left enabled in ACCESSCTRL during development (main.c leaves
`LOCK.DEBUG` clear) and secure debug is the RP2350 default while secure
boot / DEBUG_DISABLE are unburned, so the probe sees both S and NS state.

## The tz_diag record — first thing to read after any hang

Fixed address **0x20080000** (Secure SRAM8; layout in `monitor/tz_diag.h`):

```
(gdb) source mrbgems/picoruby-r2p2/tz/tools/tz_diag.gdb
(gdb) tzdiag
```

or raw: `x/12wx 0x20080000` (openocd: `mdw 0x20080000 12`). Fields, in
order: magic "TZDG" | boot_stage | fault_kind | pc | lr | xpsr | msp_ns |
cfsr | hfsr | bfar | sfsr | sfar.

- **boot_stage** 1..5 = entered / NS-verified / keys-derived / partitioned
  / blxns-issued. A hang with fault_kind 0 localizes to the stage after
  the last one stamped.
- **fault_kind** 3/4/5/6/7 = Hard/MemManage/Bus/Usage/SecureFault (the
  Secure handler that ran; NS faults escalate there). 0x100 = NS image
  hash mismatch, 0x101 = keystore init failed.
- **pc** = faulting NS instruction (map with
  `arm-none-eabi-addr2line -e <NS>.elf <pc>`); 0xbadadd50 = the NS stack
  pointer looked bogus, trust cfsr/bfar/sfar instead.

The monitor parks in a `wfi` loop after filling the record (no LED on the
2 W — GPIO25 is the CYW43 chip select). `halt` in openocd, then read.

## Build flavors

- Pico 2 (non-W, board 1): default monitor build — LED breadcrumbs AND
  the record.
- Pico 2 W / production: configure the monitor with
  `cmake -B build -S . -DR2P2_TZ_LED_DIAG=0` — record only.

NS-side aborts (`_exit`, see `ns/exit_ns.c`) print a one-shot report over
CDC, then hit `bkpt`: probe attached → core halts there with a usable
backtrace; no probe → escalates to the monitor's HardFault handler and
lands in tz_diag like everything else.
