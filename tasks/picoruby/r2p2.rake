require "fileutils"

R2P2_GEM_DIR = "#{MRUBY_ROOT}/mrbgems/picoruby-r2p2"
load "#{R2P2_GEM_DIR}/r2p2_config.rb"

ENV["PICO_SDK_PATH"] ||= "#{R2P2_GEM_DIR}/lib/pico-sdk"
ENV["PICO_EXTRAS_PATH"] ||= "#{R2P2_GEM_DIR}/lib/pico-extras"

# TZ builds use a dedicated `-tz` build config when one exists (e.g.
# r2p2-picoruby-pico2_w-tz.rb trims the gem set for the NS image); boards
# whose TZ gem set matches stock (pico2) just share the stock config.
def r2p2_mruby_config_name(vm, board)
  name = "r2p2-#{vm}-#{board}"
  tz_name = "#{name}-tz"
  if ENV["R2P2_TRUSTZONE"] && File.exist?("#{MRUBY_ROOT}/build_config/#{tz_name}.rb")
    tz_name
  else
    name
  end
end

def r2p2_mruby_config(vm, board)
  "#{MRUBY_ROOT}/build_config/#{r2p2_mruby_config_name(vm, board)}.rb"
end

def r2p2_def_board(board)
  case board
  when 'pico2_w'
    '-D PICO_PLATFORM=rp2350 -D PICO_BOARD=pico2_w -D USE_WIFI=1'
  when 'pico2'
    '-D PICO_PLATFORM=rp2350 -D PICO_BOARD=pico2'
  when 'pico_w'
    '-D PICO_PLATFORM=rp2040 -D PICO_BOARD=pico_w -D USE_WIFI=1'
  else
    '-D PICO_PLATFORM=rp2040 -D PICO_BOARD=pico'
  end
end

def r2p2_def_build_type(mode)
  case mode
  when 'debug'
    "-D CMAKE_BUILD_TYPE=Debug -D PICORB_DEBUG=1"
  else
    "-D CMAKE_BUILD_TYPE=Release -D NDEBUG=1"
  end
end

def r2p2_def_r2p2_name(vm, board)
  version = File.read("#{MRUBY_ROOT}/include/version.h").match(/#define PICORUBY_VERSION "(.+?)"/)[1]
  "-D R2P2_NAME=R2P2-#{vm.upcase} -D R2P2_BOARD_NAME=#{board.upcase} -D R2P2_VERSION=#{version}"
end

def r2p2_def_picorb_vm(vm)
  vm == 'femtoruby' ? '-D PICORB_VM_MRUBYC=1' : '-D PICORB_VM_MRUBY=1'
end

def r2p2_def_psg_mcp4922_dma
  value = ENV["PICORUBY_PSG_MCP4922_DMA"]
  enabled = !value || !%w[0 off false no n].include?(value.downcase)
  "-D PICORUBY_PSG_MCP4922_DMA=#{enabled ? 'ON' : 'OFF'}"
end

def r2p2_def_psg_pwm_dma
  value = ENV["PICORUBY_PSG_PWM_DMA"]
  enabled = !value || !%w[0 off false no n].include?(value.downcase)
  "-D PICORUBY_PSG_PWM_DMA=#{enabled ? 'ON' : 'OFF'}"
end

# The monitor is built once per board (the W build must set
# R2P2_TZ_LED_DIAG=0 — GP25 is the CYW43 chip select there). Keep the
# per-board builds in separate dirs so board-1 (pico2) artifacts survive.
def r2p2_tz_monitor_build_dir(board)
  suffix = board == "pico2" ? "" : "-#{board}"
  "#{R2P2_GEM_DIR}/tz/monitor/build#{suffix}"
end

def r2p2_def_trustzone(vm, board)
  return "" unless ENV["R2P2_TRUSTZONE"]
  unless vm == "picoruby" && %w[pico2 pico2_w].include?(board)
    raise "R2P2_TRUSTZONE is only supported for picoruby on pico2/pico2_w (RP2350 Arm)"
  end
  monitor_build = r2p2_tz_monitor_build_dir(board)
  implib = ENV["R2P2_TZ_IMPLIB"] || "#{monitor_build}/r2p2_sg_implib.o"
  unless File.exist?(implib)
    raise <<~MSG
      Monitor veneer implib not found at:
        #{implib}
      Build the Secure monitor first:
        cd #{R2P2_GEM_DIR}/tz/monitor && \\
          PICO_SDK_PATH=#{ENV['PICO_SDK_PATH']} cmake -B #{File.basename(monitor_build)} -S . -DPICO_BOARD=#{board} && \\
          cmake --build #{File.basename(monitor_build)}
      (the monitor CMakeLists forces the diag LED off on pico2_w — GP25 is
      the CYW43 chip select there) or set R2P2_TZ_IMPLIB to its
      r2p2_sg_implib.o.
    MSG
  end
  "-D R2P2_TRUSTZONE=1 -D R2P2_TZ_IMPLIB=#{implib}"
end

def r2p2_build_dir(vm, board, mode)
  suffix = ENV["R2P2_TRUSTZONE"] ? "-tz" : ""
  "#{MRUBY_ROOT}/build/r2p2/#{vm}/#{board}/#{mode}#{suffix}"
end

namespace :r2p2 do
  namespace :tz do
    # Ship-together packaging (see mrbgems/picoruby-r2p2/tz/README.md):
    # hash the built NS image, patch the digest into the monitor's
    # .ns_manifest section, regenerate the monitor UF2, optionally seal
    # with a signing key (R2P2_TZ_SIGKEY), and emit a combined UF2.
    # Layout must match tz_ns_manifest_t in tz/include/r2p2_tz_config.h.
    desc "Patch NS digest into the TZ monitor and package (env: R2P2_TZ_BOARD=pico2|pico2_w, R2P2_TZ_MODE=prod|debug, R2P2_TZ_SIGKEY, R2P2_TZ_NS_VERSION)"
    task :package do
      require "digest"

      mode = ENV["R2P2_TZ_MODE"] || "prod"
      board = ENV["R2P2_TZ_BOARD"] || "pico2"
      unless %w[pico2 pico2_w].include?(board)
        raise "R2P2_TZ_BOARD must be pico2 or pico2_w"
      end
      monitor_build = r2p2_tz_monitor_build_dir(board)
      monitor_elf = "#{monitor_build}/r2p2_tz_monitor.elf"
      ns_dir = "#{MRUBY_ROOT}/build/r2p2/picoruby/#{board}/#{mode}-tz"
      ns_bin = Dir["#{ns_dir}/R2P2-*.bin"].max_by { |f| File.mtime(f) }
      ns_uf2 = ns_bin&.sub(/\.bin\z/, ".uf2")

      raise "Monitor not built: #{monitor_elf}" unless File.exist?(monitor_elf)
      raise "NS image not built in #{ns_dir} (run the r2p2:picoruby:#{board}:#{mode} task with R2P2_TRUSTZONE=1)" unless ns_bin

      picotool = Dir["#{monitor_build}/_deps/picotool*/picotool",
                     "#{ns_dir}/_deps/picotool*/picotool"].find { |f| File.executable?(f) } || "picotool"

      ns_bytes = File.binread(ns_bin)
      digest = Digest::SHA256.digest(ns_bytes)
      magic = 0x52324e53 # TZ_NS_MANIFEST_MAGIC "R2NS"
      version = (ENV["R2P2_TZ_NS_VERSION"] || 0).to_i
      manifest = [magic, version, ns_bytes.bytesize].pack("V3") + digest

      out_dir = "#{ns_dir}/package"
      FileUtils.mkdir_p out_dir
      manifest_bin = "#{out_dir}/ns_manifest.bin"
      patched_elf = "#{out_dir}/r2p2_tz_monitor_packaged.elf"
      File.binwrite(manifest_bin, manifest)

      sh "arm-none-eabi-objcopy --update-section .ns_manifest=#{manifest_bin} #{monitor_elf} #{patched_elf}"

      if ENV["R2P2_TZ_SIGKEY"]
        # Seal AFTER patching so the signature covers the digest. Syntax:
        # `picotool seal --sign <in> <out> <secp256k1-key.pem> [otp.json]`
        # — the otp.json records the BOOTKEY fingerprint rows this key
        # needs; keep it next to the artifacts for the (irreversible,
        # board-1-only) secure-boot enable step later.
        sealed_elf = "#{out_dir}/r2p2_tz_monitor_sealed.elf"
        otp_json = "#{out_dir}/bootkey_otp.json"
        sh "#{picotool} seal --quiet --sign #{patched_elf} #{sealed_elf} #{ENV['R2P2_TZ_SIGKEY']} #{otp_json}"
        FileUtils.mv sealed_elf, patched_elf
      end

      monitor_uf2 = "#{out_dir}/r2p2_tz_monitor_packaged.uf2"
      sh "#{picotool} uf2 convert --quiet #{patched_elf} #{monitor_uf2}"

      # UF2 blocks are self-addressing; concatenation flashes both images
      # in one BOOTSEL drop (both are rp2350-arm-s family for now — the NS
      # image is entered by the monitor, never by the bootrom).
      combined = "#{out_dir}/R2P2-TZ-combined.uf2"
      File.binwrite(combined, File.binread(monitor_uf2) + File.binread(ns_uf2))

      puts "NS image:  #{ns_bin} (#{ns_bytes.bytesize} bytes)"
      puts "SHA-256:   #{digest.unpack1('H*')}"
      puts "Packaged:  #{patched_elf}#{ENV['R2P2_TZ_SIGKEY'] ? ' (sealed)' : ' (UNSIGNED dev package)'}"
      puts "Combined:  #{combined}"
    end
  end

  desc "Initialize git submodules for R2P2"
  task :setup do
    FileUtils.cd MRUBY_ROOT do
      sh "git submodule update --init --recursive mrbgems/picoruby-r2p2/lib/pico-sdk"
      sh "git submodule update --init --recursive mrbgems/picoruby-r2p2/lib/pico-extras"
      sh "git submodule update --init mrbgems/picoruby-r2p2/lib/rp2040js"
    end
  end

  task :check_pico_sdk => :check_pico_sdk_path do
    FileUtils.cd ENV['PICO_SDK_PATH'] do
      if `git describe --tags --exact-match`.chomp != PICO_SDK_TAG
        raise <<~MSG
          pico-sdk #{PICO_SDK_TAG} is not checked out!\n
          Tips for dealing with:\n
          cd #{ENV['PICO_SDK_PATH']} && \\
            git fetch origin --tags && \\
            git checkout #{PICO_SDK_TAG} && \\
            git submodule update --recursive\n
        MSG
      end
    end
    FileUtils.cd ENV['PICO_EXTRAS_PATH'] do
      if `git describe --tags --exact-match`.chomp != PICO_EXTRAS_TAG
        raise <<~MSG
          pico-extras #{PICO_EXTRAS_TAG} is not checked out!\n
          Tips for dealing with:\n
          cd #{ENV['PICO_EXTRAS_PATH']} && \\
            git fetch origin --tags && \\
            git checkout #{PICO_EXTRAS_TAG} && \\
            git submodule update --recursive\n
        MSG
      end
    end
  end

  task :check_pico_sdk_path do
    %w(PICO_SDK_PATH PICO_EXTRAS_PATH).each do |env|
      unless ENV[env]
        raise <<~MSG
          Environment variable `#{env}` does not exist!
        MSG
      end
    end
    # Check that pico-sdk submodules (e.g. tinyusb) are checked out
    pico_sdk_path = ENV['PICO_SDK_PATH']
    unless File.exist?("#{pico_sdk_path}/lib/tinyusb/src/tusb.h")
      raise <<~MSG
        pico-sdk submodules are not checked out!
        Run: cd #{pico_sdk_path} && git submodule update --init --recursive
      MSG
    end
  end

  %w[femtoruby picoruby].each do |vm|
    namespace vm do
      %w[pico pico_w pico2 pico2_w].each do |board|
        config_file = "#{MRUBY_ROOT}/build_config/r2p2-#{vm}-#{board}.rb"
        next unless File.exist?(config_file)

        namespace board do
          %w[debug prod].each do |mode|
            desc "Build R2P2 #{vm} for #{board} (#{mode})"
            task mode => "r2p2:check_pico_sdk" do
              dir = r2p2_build_dir(vm, board, mode)
              FileUtils.mkdir_p dir
              config = r2p2_mruby_config(vm, board)
              config_name = r2p2_mruby_config_name(vm, board)
              mruby_build_path = "#{MRUBY_ROOT}/build/#{config_name}"
              FileUtils.cd MRUBY_ROOT do
                sh "MRUBY_CONFIG=#{config} PICORB_BOARD=#{board} #{mode=='debug' ? 'PICORB_DEBUG=1' : ''} rake"
              end
              defs = <<~DEFS
                -D PICORUBY_ROOT=#{MRUBY_ROOT} \
                -D R2P2_GEM_DIR=#{R2P2_GEM_DIR} \
                -D EXTRA_LIBRARY_PATH=#{mruby_build_path}/lib \
                -D EXTRA_INCLUDE_DIR=#{mruby_build_path}/include \
                -D PICO_CYW43_SUPPORTED=1 \
                -D MRUBY_CONFIG=#{config_name} \
                #{r2p2_def_picorb_vm(vm)} \
                #{r2p2_def_r2p2_name(vm, board)} \
                #{r2p2_def_board(board)} \
                #{r2p2_def_build_type(mode)} \
                #{r2p2_def_psg_mcp4922_dma} \
                #{r2p2_def_psg_pwm_dma} \
                #{r2p2_def_trustzone(vm, board)}
              DEFS
              sh "cmake -S #{R2P2_GEM_DIR}/cmake -B #{dir} #{defs}"
              sh "cmake --build #{dir}"
            end
          end

          desc "Clean R2P2 #{vm} for #{board} (both debug and prod)"
          task :clean do
            FileUtils.cd MRUBY_ROOT do
              config = r2p2_mruby_config(vm, board)
              if File.exist?(config)
                sh "MRUBY_CONFIG=#{config} rake clean"
              end
            end
            %w[debug prod].each do |mode|
              dir = r2p2_build_dir(vm, board, mode)
              FileUtils.rm_f(Dir["#{dir}/R2P2*.*"]) if Dir.exist? dir
            end
          end
        end
      end
    end
  end
end
