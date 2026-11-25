# ns_build.cmake — hook the TrustZone NS runtime trimming into the R2P2
# firmware target. SKETCH. Intended usage from picoruby-r2p2/cmake/
# CMakeLists.txt, guarded by an R2P2_TRUSTZONE option:
#
#   include(${CMAKE_CURRENT_LIST_DIR}/../tz/ns/ns_build.cmake)
#   r2p2_apply_tz_ns(${PROJECT_NAME})

# Capture this file's directory at include() time. Inside the function body
# CMAKE_CURRENT_LIST_DIR resolves to the CALLER's listfile dir, not this
# file's, so the relative source/script paths below must use this instead.
set(R2P2_TZ_NS_DIR ${CMAKE_CURRENT_LIST_DIR})

function(r2p2_apply_tz_ns TARGET)
    # Stages that cannot run Non-secure (see runtime_init_ns.c header):
    # bootrom_state_reset is an Arm-S-only ROM API.
    target_compile_definitions(${TARGET} PRIVATE
        # Let shared gem source (machine.c etc.) guard NS-incompatible code
        # (e.g. Secure-only CLOCKS/POWMAN accesses) with #ifdef R2P2_TRUSTZONE.
        R2P2_TRUSTZONE=1
        PICO_RUNTIME_SKIP_INIT_BOOTROM_RESET=1
        PICO_RUNTIME_SKIP_INIT_PER_CORE_BOOTROM_RESET=1
        # bootrom_locking_enable acquires BOOTROM_LOCK_ENABLE, a lock word in
        # BOOTRAM (0x400e0000) — Secure-only, bus-faults from NS (confirmed
        # on target 2026-07-02). The monitor already enabled bootrom locking
        # system-wide; NS bootrom calls go through secure gateways that lock
        # Secure-side, so NS neither can nor needs to hold the lock itself.
        PICO_RUNTIME_SKIP_INIT_BOOTROM_LOCKING_ENABLE=1
        # boot_locks_reset writes the hardware boot locks at BOOTRAM_BASE +
        # BOOTRAM_BOOTLOCK0_OFFSET — also Secure-only BOOTRAM (confirmed on
        # target: BusFault, faulting PC in boot_unlock_unsafe). The monitor
        # already reset the boot locks; NS must not touch them.
        PICO_RUNTIME_SKIP_INIT_BOOT_LOCKS_RESET=1
        # pico_low_power (linked for Machine.sleep since pico-sdk 2.3.0)
        # registers three stages of its own. NS never enters an SDK
        # low-power state -- sleep_ns.c routes Machine.sleep to the
        # monitor -- so none of them has work to do here, and:
        #  - low_power_reboot_check reads powman_hw->chip_reset before
        #    main: POWMAN is Secure-only, so it bus-faults from NS (the
        #    same failure as the double-tap constructor).
        #  - low_power_cache_unpin references the __persistent_data_*
        #    linker symbols, which the NS linker script does not define,
        #    and would write XIP cache maintenance.
        #  - rp2350_sleep_fix masks the whole NVIC and waits in WFI for a
        #    dummy user IRQ after a watchdog reboot; if that IRQ is not
        #    NS-pendable the image hangs before main.
        # NO_INIT drops the function, SKIP_INIT drops its registration;
        # the SDK wants both.
        PICO_RUNTIME_NO_INIT_LOW_POWER_REBOOT_CHECK=1
        PICO_RUNTIME_SKIP_INIT_LOW_POWER_REBOOT_CHECK=1
        PICO_RUNTIME_NO_INIT_LOW_POWER_CACHE_UNPIN=1
        PICO_RUNTIME_SKIP_INIT_LOW_POWER_CACHE_UNPIN=1
        PICO_RUNTIME_NO_INIT_RP2350_SLEEP_FIX=1
        PICO_RUNTIME_SKIP_INIT_RP2350_SLEEP_FIX=1
    )

    # Strong overrides for the __weak stages that must behave differently
    # in NS (early resets / clocks / post-clock resets), plus the
    # link-level pico_rand replacement (TRNG is Secure-only; rand_ns.c
    # backs get_rand_* with the sg_random_bytes veneer, which transitively
    # fixes picoruby-rng, pico_mbedtls entropy, and lwIP's RNG).
    # flash_ns.c likewise replaces hardware_flash's flash_range_erase/
    # flash_range_program with bootrom checked_flash_op calls (+ cache
    # flush via veneer), transitively fixing picoruby-filesystem-fat and
    # picoruby-littlefs.
    # aon_ns.c: pico_aon_timer onto the sg_aon_* veneers (the monitor owns
    # the POWMAN AON timer — Secure-only; survives deep sleep + reboots).
    # sleep_ns.c: Machine_sleep_timer / Machine_sleep_gpio. Deep timer
    # sleep goes onto sg_deep_sleep (the CLOCKS/PLL/POWMAN recipe runs
    # Secure-side); light timer sleep is a plain wait; GPIO wake is
    # reported as unsupported.
    target_sources(${TARGET} PRIVATE
        ${R2P2_TZ_NS_DIR}/runtime_init_ns.c
        ${R2P2_TZ_NS_DIR}/rand_ns.c
        ${R2P2_TZ_NS_DIR}/flash_ns.c
        ${R2P2_TZ_NS_DIR}/aon_ns.c
        ${R2P2_TZ_NS_DIR}/sleep_ns.c
        ${R2P2_TZ_NS_DIR}/gpio_irq_ns.c # vector IO_IRQ_BANK0_NS to the SDK's IRQ-21 handlers
        ${R2P2_TZ_NS_DIR}/exit_ns.c   # _exit override: report + bkpt (probe-friendly halt)
        ${R2P2_TZ_NS_DIR}/tz_selftest.c # `TZ.selftest` in irb: phase-2 veneer exerciser
        ${R2P2_TZ_NS_DIR}/tz_api.c      # Ruby surface: TZ.derive_key/verify_mrb, Digest::SHA256
    )

    # NB: intentionally NOT linking pico_flash. flash_ns.c calls the bootrom
    # NS flash_op secure-gateway directly (not the rom_flash_op wrapper), so
    # we avoid flash_safe_execute and its BOOTRAM lock — which is Secure-only
    # and bus-faults from NS.

    # pico_rand / hardware_flash are SDK INTERFACE libs whose .c files are
    # injected as peer objects, so rand_ns.c / flash_ns.c cannot simply
    # redefine their symbols. --wrap redirects callers to the __wrap_*
    # versions (SDK-idiomatic; the SDK uses --wrap for the AEABI doubles).
    # The originals become unreferenced and --gc-sections drops them,
    # removing the Secure-only TRNG/QSPI paths from the NS image.
    target_link_options(${TARGET} PRIVATE
        LINKER:--wrap=get_rand_32
        LINKER:--wrap=get_rand_64
        LINKER:--wrap=get_rand_128
        LINKER:--wrap=flash_range_erase
        LINKER:--wrap=flash_range_program
        LINKER:--wrap=aon_timer_start
        LINKER:--wrap=aon_timer_set_time
        LINKER:--wrap=aon_timer_get_time
        LINKER:--wrap=aon_timer_is_running
        LINKER:--wrap=Machine_sleep_timer
        LINKER:--wrap=Machine_sleep_gpio
    )

    target_include_directories(${TARGET} PRIVATE
        ${R2P2_TZ_NS_DIR}/../include
    )

    # NS memory map (monitor owns 0x10000000..0x1000ffff and SRAM8/9).
    pico_set_linker_script(${TARGET}
        ${R2P2_TZ_NS_DIR}/memmap_r2p2_ns.ld
    )

    # The veneer import library produced by the monitor link
    # (-Wl,--cmse-implib,--out-implib=r2p2_sg_implib.o). It carries the
    # sg_* veneer symbols as absolute NSC addresses (0x1000f0xx), so the NS
    # image calls them as ordinary functions. Passed in via -D from the
    # rake task (defaults to the standalone monitor build output).
    if(NOT DEFINED R2P2_TZ_IMPLIB)
        message(FATAL_ERROR
            "R2P2_TRUSTZONE set but R2P2_TZ_IMPLIB is not defined — "
            "build tz/monitor first and point R2P2_TZ_IMPLIB at "
            "its r2p2_sg_implib.o")
    endif()
    if(NOT EXISTS ${R2P2_TZ_IMPLIB})
        message(FATAL_ERROR "R2P2_TZ_IMPLIB does not exist: ${R2P2_TZ_IMPLIB}")
    endif()
    target_link_libraries(${TARGET} PRIVATE ${R2P2_TZ_IMPLIB})

    # TODO (phase 1, still open):
    #  - picotool packaging: EXE_SECURITY=NS image type, combined-image
    #    signing with the monitor, partition table with the FS partition
    #    marked NS_R/NS_W.
    # (Gem source substitutions are complete: rng/mbedtls/lwIP rand and
    # both flash HALs via rand_ns.c/flash_ns.c, wall clock via aon_ns.c,
    # Machine.sleep via sleep_ns.c; psg is excluded via the -tz build
    # configs + the psg port removal in cmake/CMakeLists.txt.)
endfunction()
