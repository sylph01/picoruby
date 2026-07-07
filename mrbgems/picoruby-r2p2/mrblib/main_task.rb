if RUBY_ENGINE == "mruby/c"
  require "numeric-ext"
end
require "machine"
require "watchdog"
Watchdog.disable
require "shell"
require "irq"
STDOUT = IO.new
STDIN = IO.new

Machine.set_hwclock(0)

if RUBY_ENGINE == "mruby"
  GC.interval_ratio = 110
end

begin
  sleep 1
  STDIN.echo = false
  puts "Initializing FLASH disk as the root volume... "
  Shell.setup_root_volume(:flash, label: "R2P2")
  Shell.setup_system_files

  Shell.bootstrap("/etc/init.d/r2p2")

  shell = Shell.new(clean: true)
  puts "Starting shell...\n\n"

  shell.show_logo
  shell.start
rescue => e
  # Keep re-printing a fatal boot error instead of letting the task die:
  # a one-shot print races USB CDC enumeration (the host usually isn't
  # listening yet), and on the TZ build a dead scheduler parks the core.
  loop do
    puts "#{e.message} (#{e.class})"
    sleep 2
  end
end

