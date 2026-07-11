MRuby::CrossBuild.new("r2p2-picoruby-pico2_w-tz") do |conf|

  ###############################################################
  # TrustZone NS build for the Pico 2 W (WiFi under the S/NS split,
  # see mrbgems/picoruby-r2p2/tz/docs/WIFI-UNDER-TZ-HANDOFF.md).
  # Mirrors r2p2-picoruby-pico2_w.rb except:
  #   - no picoruby-ble / picoruby-ble-uart: TZ is WiFi-only for now
  #     (watch-out #5 — saves the btstack link, RAM and audit surface;
  #     the CYW43 firmware blob still contains BT, we just don't drive it)
  #   - no picoruby-psg: its PSG_tick_start_core1 launches core 1, a
  #     Secure-only bootrom operation that faults under TZ until the
  #     sg_launch_core1_ns veneer exists (PHASE2-BACKLOG item 1; the
  #     matching port-source removal is in cmake/CMakeLists.txt)
  # Selected automatically by `R2P2_TRUSTZONE=1 rake r2p2:picoruby:pico2_w:*`
  # (r2p2.rake prefers a `-tz` build config when one exists).
  #
  # You need following tools:
  #   arm-none-eabi       | to make libmruby.a
  ###############################################################

  conf.toolchain("gcc")

  conf.cc.defines << "PICORB_PLATFORM_RP2"

  conf.cc.defines << "MRB_TICK_UNIT=1"
  conf.cc.defines << "MRB_TIMESLICE_TICK_COUNT=10"

  conf.cc.defines << "MRB_UTF8_STRING"
  conf.cc.defines << "MRB_INT64"
  conf.cc.defines << "MRB_NO_BOXING"
  conf.cc.defines << "MRB_32BIT"
  conf.cc.defines << "PICORB_ALLOC_ESTALLOC"
  conf.cc.defines << "PICORB_ALLOC_ALIGN=8"
  conf.cc.defines << "USE_WIFI"
  conf.cc.defines << "MRB_USE_CUSTOM_RO_DATA_P"
  conf.cc.defines << "MRB_LINK_TIME_RO_DATA_P"
  conf.cc.defines << "NO_CLOCK_GETTIME=1"

  conf.cc.command = "arm-none-eabi-gcc"
  conf.linker.command = "arm-none-eabi-ld"
  conf.linker.flags << "-static"
  conf.archiver.command = "arm-none-eabi-ar"

  conf.cc.host_command = "gcc"

  conf.cc.flags.flatten!
  conf.cc.flags << "-mcpu=cortex-m33"
  conf.cc.flags << "-mthumb"

  conf.cc.flags << "-fno-strict-aliasing"
  conf.cc.flags << "-fno-unroll-loops"
  conf.cc.flags << "-mslow-flash-data"

  conf.cc.flags << "-fshort-enums"

  conf.cc.flags << "-Wall"
  conf.cc.flags << "-Wno-format"
  conf.cc.flags << "-Wno-unused-function"
  conf.cc.flags << "-ffunction-sections"
  conf.cc.flags << "-fdata-sections"

  conf.picoruby

  conf.gembox "minimum"
  conf.gembox "core"
  conf.gembox "stdlib"
  conf.gembox "shell"
  conf.gembox "peripherals"
  conf.gembox "peripheral_utils"
  conf.gembox "networking"
  unless ENV['PICORB_DEBUG']
    # Shinonome is too big for debug build
    conf.gem core: 'picoruby-shinonome'
  end
  conf.gem core: 'picoruby-keyboard'
  # NS-side session crypto: TZ.derive_key (HKDF export from the Secure
  # keystore) feeds MbedTLS::Cipher#key= — the tier-2 session-key model.
  # (networking already pulls mbedtls for TLS; listed for explicitness.)
  conf.gem core: 'picoruby-mbedtls'
end
