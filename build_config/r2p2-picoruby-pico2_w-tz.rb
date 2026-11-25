MRuby::CrossBuild.new("r2p2-picoruby-pico2_w-tz#{ENV['PICORB_DEBUG'] ? '-debug' : ''}") do |conf|

  ###############################################################
  # TrustZone NS build for the Pico 2 W (WiFi under the S/NS split,
  # see mrbgems/picoruby-r2p2/tz/docs/WIFI-UNDER-TZ-HANDOFF.md).
  # Mirrors r2p2-picoruby-pico2_w.rb except:
  #   - no picoruby-ble / picoruby-ble-uart: TZ is WiFi-only for now
  #     (watch-out #5 — saves the btstack link, RAM and audit surface;
  #     the CYW43 firmware blob still contains BT, we just don't drive it)
  #   - no picoruby-psg: its PSG_tick_start_core1 launches core 1, a
  #     Secure-only bootrom operation (PHASE2-BACKLOG item 1; the
  #     matching port-source removal is in cmake/CMakeLists.txt)
  # Keep everything else identical to the stock config: the R2P2 CMake
  # build hard-codes the VM shape (MRB_INT32, MRB_WORD_BOXING,
  # MRB_USE_C_STACK_CHECK) and compiles every gem's rp2040 port, so a
  # libmruby built with other defines or another gem set does not match.
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
  # 32-bit word boxing: mrb_value is 4 bytes. An Integer past 31 bits is a
  # heap RInteger, and one past mrb_int is a Bignum from mruby-bigint.
  conf.cc.defines << "MRB_INT32"
  conf.cc.defines << "MRB_WORD_BOXING"
  conf.cc.defines << "MRB_32BIT"
  conf.cc.defines << "USE_WIFI"
  conf.cc.defines << "MRB_USE_CUSTOM_RO_DATA_P"
  conf.cc.defines << "MRB_LINK_TIME_RO_DATA_P"
  conf.cc.defines << "NO_CLOCK_GETTIME=1"
  # The VM checks the machine stack where C enters it and raises
  # SystemStackError before the 16KB core 0 stack overruns (a block called
  # from a C method, a C method that recurses). main.c sets the floor.
  conf.cc.defines << "MRB_USE_C_STACK_CHECK"

  # Prism arena block size. Prism's 8KB default is host-sized; a parse of a
  # REPL line uses about 6KB on a 32-bit target (most of it the constant
  # pool), so 2KB blocks waste less of the Estalloc heap. A larger single
  # allocation still fits: Prism sizes that block to it.
  conf.cc.defines << "PM_ARENA_INITIAL_SIZE=2048"
  # The constant pool starts at 128 entries: the compiler interns the 58
  # presyms into it at every parse, and a pool that grows to hold them
  # leaves each outgrown array behind in the arena.
  conf.cc.defines << "PM_CONSTANT_POOL_MIN_CAPACITY=128"
  # picoruby-regexp: the backtracker for a pattern with a backreference
  # keeps its stack under 48 KB and gives up after a million steps
  conf.cc.defines << "REGEX_BT_MAX_STACK=4096"
  conf.cc.defines << "REGEX_BT_MAX_STEPS=1000000"

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

  # PICORB_AOT=1: compile the mrblib of the gems that declare `spec.aot`
  # (json, editor, midibase-mml, keyboard) to cfuncs with picoruby-aot. A
  # gem is opted out with `conf.gem(core: 'x') { |g| g.aot = false }`.
  conf.aot if ENV['PICORB_AOT']

  conf.gem gemdir: "#{MRUBY_ROOT}/mrbgems/picoruby-mruby/lib/mruby/mrbgems/mruby-bigint"
  conf.gembox "minimum"
  conf.gembox "core"
  conf.gembox "stdlib"
  conf.gembox "shell"
  conf.gembox "peripherals"
  conf.gembox "peripheral_utils"
  conf.gembox "networking"
  conf.gem core: 'picoruby-jwt'
  unless ENV['PICORB_DEBUG']
    # Shinonome is too big for debug build
    conf.gem core: 'picoruby-shinonome'
  end
  conf.gem core: 'picoruby-midibase-mml'
  conf.gem core: 'picoruby-midibase-looper'
  conf.gem core: 'picoruby-uart-midi'
  conf.gem core: 'picoruby-usb-cdc-midi'
  conf.gem core: 'picoruby-keyboard'
  # NS-side session crypto: TZ.derive_key (HKDF export from the Secure
  # keystore) feeds MbedTLS::Cipher#key= — the tier-2 session-key model.
  # (networking already pulls mbedtls for TLS; listed for explicitness.)
  conf.gem core: 'picoruby-mbedtls'
end
