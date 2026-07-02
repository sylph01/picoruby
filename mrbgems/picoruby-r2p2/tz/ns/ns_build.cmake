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
        PICO_RUNTIME_SKIP_INIT_BOOTROM_RESET=1
        PICO_RUNTIME_SKIP_INIT_PER_CORE_BOOTROM_RESET=1
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
    target_sources(${TARGET} PRIVATE
        ${R2P2_TZ_NS_DIR}/runtime_init_ns.c
        ${R2P2_TZ_NS_DIR}/rand_ns.c
        ${R2P2_TZ_NS_DIR}/flash_ns.c
    )

    # rom_flash_op() serializes through flash_safe_execute().
    # Keyword (PRIVATE) form to match the R2P2 CMakeLists' usage.
    target_link_libraries(${TARGET} PRIVATE pico_flash)

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
    #  - gem source substitutions for the TZ build (see tz/README.md
    #    "NS build: gem impact"): machine sleep/time paths; exclude
    #    psg/pitchdetector. (rng/mbedtls/lwIP rand and both flash HALs
    #    are already covered by rand_ns.c / flash_ns.c above.)
endfunction()
