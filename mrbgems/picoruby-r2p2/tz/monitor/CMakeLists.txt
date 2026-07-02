# R2P2 TrustZone Secure monitor — standalone CMake project. SKETCH.
#
# Build (pico-sdk 2.2.0, PICO_SDK_PATH set):
#   cmake -B build -S . && cmake --build build
#
# Products:
#   r2p2_tz_monitor.elf/.uf2 — the Secure monitor (flash 0x10000000)
#   r2p2_sg_implib.o         — CMSE import library; the NS R2P2 build links
#                              this to reach the sg_* veneers (ns_build.cmake)

cmake_minimum_required(VERSION 3.13)

# Secure Cortex-M33 platform; -mcmse is the SDK toolchain default here.
set(PICO_PLATFORM rp2350-arm-s CACHE STRING "")
set(PICO_BOARD pico2 CACHE STRING "")

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(r2p2_tz_monitor C CXX ASM)
pico_sdk_init()

add_executable(r2p2_tz_monitor
    main.c
    sg_veneers.c
)

target_compile_definitions(r2p2_tz_monitor PRIVATE
    R2P2_TZ_MONITOR=1   # r2p2_sg_api.h: SG_API -> cmse_nonsecure_entry
    PICO_SECURE=1       # unlocks gpio_assign_to_ns()/irq_assign_to_ns()
)

target_include_directories(r2p2_tz_monitor PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include)

# Deliberately NOT pico_stdlib: no stdio, no UART, no alarm pool — every
# library here is part of the trusted computing base, keep it minimal.
target_link_libraries(r2p2_tz_monitor
    pico_runtime    # crt0, runtime init (stock Secure init: clocks, ticks, resets)
    pico_bootrom    # rom_flash_op lock plumbing, rom_set_ns_api_permission, ...
    pico_rand       # TRNG-backed generator feeding sg_random_bytes
    pico_sha256     # hardware SHA-256 behind sg_sha256 (and HKDF later)
    hardware_gpio   # gpio_assign_to_ns
    hardware_irq    # irq_assign_to_ns
)

pico_set_linker_script(r2p2_tz_monitor ${CMAKE_CURRENT_LIST_DIR}/memmap_monitor_s.ld)

# CMSE secure gateway: emit veneers for every cmse_nonsecure_entry function
# into .gnu.sgstubs (placed at TZ_SG_NSC_BASE by the linker script) and
# produce the import library the NS image links against.
set(R2P2_SG_IMPLIB ${CMAKE_BINARY_DIR}/r2p2_sg_implib.o CACHE FILEPATH "")
target_link_options(r2p2_tz_monitor PRIVATE
    "LINKER:--cmse-implib"
    "LINKER:--out-implib=${R2P2_SG_IMPLIB}"
    # When reflashing a new monitor against an already-linked NS image, pin
    # the veneer addresses to the previous ABI:
    # "LINKER:--in-implib=${R2P2_SG_IMPLIB_PREVIOUS}"
)

pico_add_extra_outputs(r2p2_tz_monitor)

# ---- signing (production) ---------------------------------------------------
# Dev boards boot the partition unsigned; secure boot (OTP CRIT1.
# SECURE_BOOT_ENABLE, irreversible — README) is what makes the monitor
# non-bypassable. The signature must cover the COMBINED monitor+NS image
# (single signed unit, see README "Phase-1 decisions"), so plain
# pico_sign_binary() on this target alone is only correct for
# monitor-without-NS testing. TODO: packaging step that concatenates
# monitor + NS R2P2 at their linked offsets and signs the whole range
# (picotool seal --sig <key.pem> combined.bin, or extend the IMAGE_DEF
# load map to cover the NS region).
option(R2P2_TZ_SIGN "Sign the monitor image (requires R2P2_TZ_SIGKEY)" OFF)
if (R2P2_TZ_SIGN)
    pico_sign_binary(r2p2_tz_monitor ${R2P2_TZ_SIGKEY})
endif()

# ---- crypto slice (TODO: keystore/HKDF/AEAD veneers) -------------------------
# The symmetric slice of the SDK-vendored mbedTLS — no bignum/ECP, a few
# KiB of code, few hundred bytes of stack. Wire up together with a minimal
# MBEDTLS_CONFIG_FILE (chacha20/poly1305/chachapoly/hkdf/md/sha256) when
# the sg_key_*/sg_aead_*/sg_hmac_* stubs get real implementations:
#
# set(MBEDTLS_LIB $ENV{PICO_SDK_PATH}/lib/mbedtls/library)
# target_sources(r2p2_tz_monitor PRIVATE
#     ${MBEDTLS_LIB}/chacha20.c ${MBEDTLS_LIB}/poly1305.c
#     ${MBEDTLS_LIB}/chachapoly.c ${MBEDTLS_LIB}/hkdf.c
#     ${MBEDTLS_LIB}/md.c ${MBEDTLS_LIB}/sha256.c
#     ${MBEDTLS_LIB}/constant_time.c ${MBEDTLS_LIB}/platform_util.c)
# target_compile_definitions(r2p2_tz_monitor PRIVATE
#     MBEDTLS_CONFIG_FILE="mbedtls_config_monitor.h")
