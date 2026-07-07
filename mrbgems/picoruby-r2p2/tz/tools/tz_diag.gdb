# tz_diag.gdb — pretty-print the monitor's diagnostic record (tz_diag.h).
#   (gdb) source tz/tools/tz_diag.gdb
#   (gdb) tzdiag

define tzdiag
  set $d = (unsigned int *)0x20080000
  if $d[0] != 0x545a4447
    printf "tz_diag: bad magic 0x%08x (monitor never initialized it?)\n", $d[0]
  else
    printf "boot_stage: %u  (1 entered, 2 ns-verified, 3 keys, 4 partitioned, 5 blxns)\n", $d[1]
    if $d[2] == 0
      printf "fault_kind: none\n"
    else
      printf "fault_kind: 0x%x (3 hard, 4 mem, 5 bus, 6 usage, 7 secure; 0x100 ns-hash, 0x101 keystore)\n", $d[2]
      printf "pc:   0x%08x   (arm-none-eabi-addr2line -e <ns>.elf)\n", $d[3]
      printf "lr:   0x%08x   xpsr: 0x%08x   msp_ns: 0x%08x\n", $d[4], $d[5], $d[6]
      printf "cfsr: 0x%08x   hfsr: 0x%08x\n", $d[7], $d[8]
      printf "bfar: 0x%08x   sfsr: 0x%08x   sfar: 0x%08x\n", $d[9], $d[10], $d[11]
    end
  end
end

document tzdiag
Print the R2P2-TZ monitor diagnostic record at 0x20080000 (tz_diag.h).
end
