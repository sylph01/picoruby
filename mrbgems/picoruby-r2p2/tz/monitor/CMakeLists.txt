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

# The symmetric slice of the SDK-vendored mbedTLS (3.6): just the ChaCha20
# and Poly1305 primitives — the AEAD construction, HKDF and HMAC are
# sg_crypto.c over the hardware SHA-256. No md layer, no bignum/ECP.
set(MBEDTLS_LIB $ENV{PICO_SDK_PATH}/lib/mbedtls/library)

add_executable(r2p2_tz_monitor
    main.c
    sg_veneers.c
    sg_crypto.c
    keystore.c
    vendor/micro-ecc/uECC.c
    ${MBEDTLS_LIB}/chacha20.c
    ${MBEDTLS_LIB}/poly1305.c
    ${MBEDTLS_LIB}/platform_util.c
)

target_compile_definitions(r2p2_tz_monitor PRIVATE
    R2P2_TZ_MONITOR=1   # r2p2_sg_api.h: SG_API -> cmse_nonsecure_entry
    PICO_SECURE=1       # unlocks gpio_assign_to_ns()/irq_assign_to_ns()
    MBEDTLS_CONFIG_FILE="mbedtls_config_monitor.h"
    # micro-ecc (sg_verify_mrb): P-256 verify only; all inputs are public,
    # so the small non-hardened verify path is exactly what we want.
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=0
    uECC_SUPPORTS_secp256r1=1
    uECC_SUPPORTS_secp256k1=0
    uECC_SUPPORT_COMPRESSED_POINT=0
    # RAM budget (8 KiB total, SRAM8+9): stack must absorb uECC_verify's
    # ~1.5 KiB transient on top of veneer frames; the monitor barely mallocs
    # (heap trimmed accordingly). Re-measure on any crypto change — the
    # linker does NOT warn about stack overflow into .bss.
    PICO_STACK_SIZE=0x1000
    PICO_HEAP_SIZE=0x100
    # RAM_S is 8 KiB; drop runtime-init conveniences the monitor never uses:
    # no runtime IRQ handler swapping (vectors stay in Secure flash) and no
    # default alarm pool (busy_delay is a spin loop).
    PICO_NO_RAM_VECTOR_TABLE=1
    PICO_TIME_DEFAULT_ALARM_POOL_DISABLED=1
    # Anti-rollback counter OTP writes stay compiled OUT for dev boards; a
    # RAM shadow keeps the semantics. Production monitors set this to 1.
    R2P2_TZ_OTP_WRITE=0
)

target_include_directories(r2p2_tz_monitor PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}                       # mbedtls_config_monitor.h, mrb_pubkey.h
    ${CMAKE_CURRENT_LIST_DIR}/../include
    $ENV{PICO_SDK_PATH}/lib/mbedtls/include
    ${MBEDTLS_LIB}                                  # mbedtls' internal common.h
)

# Deliberately NOT pico_stdlib: no stdio, no UART, no alarm pool — every
# library here is part of the trusted computing base, keep it minimal.
target_link_libraries(r2p2_tz_monitor
    pico_runtime    # crt0, runtime init (stock Secure init: clocks, ticks, resets)
    pico_bootrom    # rom_flash_op lock plumbing, rom_set_ns_api_permission, ...
    pico_rand       # TRNG-backed generator feeding sg_random_bytes
    pico_sha256     # hardware SHA-256 behind sg_sha256 (and HKDF later)
    hardware_flash  # flash_range_erase/program behind sg_flash_* (RAM-resident)
    hardware_gpio   # gpio_assign_to_ns
    hardware_irq    # irq_assign_to_ns
)

pico_set_linker_script(r2p2_tz_monitor ${CMAKE_CURRENT_LIST_DIR}/memmap_monitor_s.ld)

# Partition table embedded in the monitor (the boot image) — "partition-
# table-in-image boot", datasheet §5.1.14. Defines flash permissions:
# firmware region has nonsecure="" (NS cannot reflash the monitor or NS
# image via checked_flash_op), the fs partition has nonsecure="rw" (what
# makes flash_ns.c's NS writes accepted). The firmware partition accepts
# BOTH rp2350-arm-s and rp2350-arm-ns families so the combined UF2 drop
# routes the monitor and NS halves correctly. picotool embeds this at
# POST_BUILD; rake r2p2:tz:package's objcopy/seal run on top afterwards.
pico_embed_pt_in_binary(r2p2_tz_monitor ${CMAKE_CURRENT_LIST_DIR}/r2p2_tz_pt.json)

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
# Signing does NOT happen here. Ship-together model (README "Phase-1
# decisions"): the NS image's SHA-256 must be patched into .ns_manifest
# BEFORE sealing, and the NS image doesn't exist yet when this target
# builds (it links our implib). The pipeline is:
#   1. build this monitor (placeholder manifest, magic=0 -> dev boot
#      skips the NS hash check)
#   2. build the NS R2P2 (R2P2_TRUSTZONE=1 rake r2p2:picoruby:pico2:prod)
#   3. rake r2p2:tz:package   # hash NS -> objcopy .ns_manifest ->
#                             # picotool seal (R2P2_TZ_SIGKEY) -> UF2s
# Secure boot (OTP CRIT1.SECURE_BOOT_ENABLE, irreversible — README) is what
# makes the monitor non-bypassable; the monitor's signature then covers the
# manifest, which covers the NS bytes.

# ---- signing key (sg_verify_mrb) ---------------------------------------------
# mrb_pubkey.h is generated: tools/mrb_sign.rb pubkey <key.pem> mrb_pubkey.h
# The committed mrb_signing_dev.pem is a DEV key (private half in-repo, so
# it authenticates nothing). Before enabling secure boot for real, generate
# a fresh keypair off-repo and regenerate the header.
