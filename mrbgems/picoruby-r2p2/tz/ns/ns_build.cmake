# ns_build.cmake — hook the TrustZone NS runtime trimming into the R2P2
# firmware target. SKETCH. Intended usage from picoruby-r2p2/cmake/
# CMakeLists.txt, guarded by an R2P2_TRUSTZONE option:
#
#   include(${CMAKE_CURRENT_LIST_DIR}/../tz/ns/ns_build.cmake)
#   r2p2_apply_tz_ns(${PROJECT_NAME})

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
    target_sources(${TARGET} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/runtime_init_ns.c
        ${CMAKE_CURRENT_LIST_DIR}/rand_ns.c
    )

    target_include_directories(${TARGET} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/../include
    )

    # NS memory map (monitor owns 0x10000000..0x1000ffff and SRAM8/9).
    pico_set_linker_script(${TARGET}
        ${CMAKE_CURRENT_LIST_DIR}/memmap_r2p2_ns.ld
    )

    # The veneer import library produced by the monitor link
    # (-Wl,--cmse-implib,--out-implib=r2p2_sg_implib.o). Path TBD once the
    # monitor CMake project exists:
    # target_link_libraries(${TARGET} ${R2P2_TZ_IMPLIB})

    # TODO (phase 1, still open):
    #  - picotool packaging: EXE_SECURITY=NS image type, combined-image
    #    signing with the monitor, partition table with the FS partition
    #    marked NS_R/NS_W.
    #  - gem source substitutions for the TZ build (see tz/README.md
    #    "NS build: gem impact"): flash HALs (checked_flash_op), machine
    #    sleep paths; exclude psg/pitchdetector. (rng/mbedtls/lwIP rand
    #    needs are already covered by rand_ns.c above.)
endfunction()
