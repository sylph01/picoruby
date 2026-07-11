MRuby::Gem::Specification.new('picoruby-machine') do |spec|
  spec.license = 'MIT'
  spec.author  = 'HASUMI Hitoshi'
  spec.summary = 'Machine class'

  spec.add_dependency 'picoruby-require'
  spec.add_dependency 'picoruby-io-console'

  if build.posix?
    # The POSIX port runs a dedicated stdin reader thread to emulate the
    # UART/CDC RX interrupt used on bare-metal targets (see ports/posix/machine.c).
    spec.cc.flags << '-pthread'
    spec.linker.flags << '-pthread'
  end

  if build.gems.map(&:name).include?('picoruby-mruby')
    # Workaround:
    #   Locate mruby-io at the top of gem_init.c
    #   to define IO.open earlier than this gems
    if build.posix?
      spec.add_dependency 'mruby-io'
    end
    # This gem implements mruby-task's HAL (hal.h aliases picorb_hal_* to
    # mrb_hal_task_*); depend on it so task_hal.h — the contract being
    # implemented, including mrb_task_switch_reason — is on the include path.
    spec.add_dependency 'mruby-task', gemdir: "#{MRUBY_ROOT}/mrbgems/picoruby-mruby/lib/mruby/mrbgems/mruby-task"
  end
end
