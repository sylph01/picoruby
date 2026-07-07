cmake_minimum_required(VERSION 3.22)

#set(CMAKE_VERBOSE_MAKEFILE ON)

include(pico_sdk_import.cmake)
include(pico_extras_import.cmake)

# Initialize the SDK
pico_sdk_init()

execute_process (COMMAND date +%Y%m%d OUTPUT_VARIABLE CMAKE_BUILDDATE OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND git rev-parse --short HEAD OUTPUT_VARIABLE CMAKE_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE WORKING_DIRECTORY ${PICORUBY_ROOT})
# R2P2_VERSION is passed via -D from rake task
set (R2P2_BUILDDATE ${CMAKE_BUILDDATE})
set (R2P2_REVISION  ${CMAKE_REVISION})

project("${R2P2_NAME}-${R2P2_VERSION}-${R2P2_BOARD_NAME}-${R2P2_BUILDDATE}-${R2P2_REVISION}")

# Non-secure half of a TrustZone-split R2P2 (RP2350 Arm: pico2/pico2_w).
# See ${R2P2_GEM_DIR}/tz/README.md. When ON, the runtime-init/rand/flash
# overrides, the NS linker script, and the monitor's veneer implib are
# applied via tz/ns/ns_build.cmake (near the end of this file).
option(R2P2_TRUSTZONE "Build the Non-secure half of a TrustZone-split R2P2 (pico2/pico2_w)" OFF)

add_compile_options(-Wall
  # int != int32_t as far as the compiler is concerned because gcc has int32_t as long int
  -Wno-format
  -Wno-unused-function
  -ffunction-sections
  -fdata-sections
  -fshort-enums
  -mthumb
)

if(PICORB_DEBUG)
  add_compile_definitions(PICORB_DEBUG=1)
  add_compile_options(
    -O0
    -g3
  )
else()
  add_compile_definitions(NDEBUG=1)
  add_compile_options(
    -O2
  )
endif()

file(GLOB SOURCE_FILES CONFIGURE_DEPENDS
  ${PICORUBY_ROOT}/mrbgems/*/ports/rp2040/*.c
  ${PICORUBY_ROOT}/mrbgems/*/ports/common/*.c
)
if(USE_WIFI)
  add_compile_definitions(USE_WIFI=1)
  file(GLOB ADD_WIFI_SOURCE_FILES CONFIGURE_DEPENDS
    ${PICO_SDK_PATH}/src/rp2_common/pico_mbedtls/pico_mbedtls.c
  )
  list(APPEND SOURCE_FILES ${ADD_WIFI_SOURCE_FILES})
  if(PICO_BOARD STREQUAL "pico2_w")
    file(GLOB REMOVE_WIFI_SRCS CONFIGURE_DEPENDS
      ${PICORUBY_ROOT}/mrbgems/picoruby-filesystem-fat/ports/rp2040/*.c
      ${PICORUBY_ROOT}/mrbgems/picoruby-net/ports/rp2040/*.c
    )
  else()
    # pico_w uses picoruby-socket instead of picoruby-net to avoid function conflicts
    file(GLOB REMOVE_WIFI_SRCS CONFIGURE_DEPENDS
      ${PICORUBY_ROOT}/mrbgems/picoruby-filesystem-fat/ports/rp2040/*.c
      ${PICORUBY_ROOT}/mrbgems/picoruby-net/ports/rp2040/*.c
    )
  endif()
  if(R2P2_TRUSTZONE)
    # TZ is WiFi-only (no Bluetooth, see tz/docs/WIFI-UNDER-TZ-HANDOFF.md
    # watch-out #5): the r2p2-picoruby-pico2_w-tz build config drops the
    # BLE gems from libmruby, so the BLE port .c (which needs btstack
    # headers we no longer pull in) must not be compiled either.
    file(GLOB REMOVE_BLE_SRCS CONFIGURE_DEPENDS
      ${PICORUBY_ROOT}/mrbgems/picoruby-ble/ports/rp2040/*.c
    )
    list(APPEND REMOVE_WIFI_SRCS ${REMOVE_BLE_SRCS})
  endif()
else()
  # picoruby-mbedtls stays IN for non-WiFi builds: the pico2 build config
  # now includes the gem (NS session crypto under TrustZone, see
  # tz/README.md), whose src/*.c inside libmruby.a reference the MbedTLS_*
  # port symbols, and whose entropy module needs the SDK's
  # mbedtls_hardware_poll (pico_mbedtls.c). Under TZ that glue's
  # get_rand_64() call is --wrap'ed by tz/ns/rand_ns.c onto
  # sg_random_bytes — the wrap comment lists it as a known caller. The
  # port objects must see the SAME mbedtls config the gem's rake-side
  # library objects were built with — context structs are sized by it.
  add_compile_definitions(
    MBEDTLS_CONFIG_FILE="${PICORUBY_ROOT}/mrbgems/picoruby-mbedtls/include/mbedtls_config.h"
  )
  file(GLOB ADD_MBEDTLS_GLUE CONFIGURE_DEPENDS
    ${PICO_SDK_PATH}/src/rp2_common/pico_mbedtls/pico_mbedtls.c
  )
  list(APPEND SOURCE_FILES ${ADD_MBEDTLS_GLUE})
  file(GLOB REMOVE_WIFI_SRCS CONFIGURE_DEPENDS
      ${PICORUBY_ROOT}/mrbgems/picoruby-filesystem-fat/ports/rp2040/*.c
    ${PICORUBY_ROOT}/mrbgems/picoruby-cyw43/ports/rp2040/*.c
    ${PICORUBY_ROOT}/mrbgems/picoruby-net/ports/rp2040/*.c
    ${PICORUBY_ROOT}/mrbgems/picoruby-socket/ports/rp2040/*.c
    ${PICORUBY_ROOT}/mrbgems/picoruby-ble/ports/rp2040/*.c
  )
endif()

list(REMOVE_ITEM SOURCE_FILES ${REMOVE_WIFI_SRCS})

if(PICORB_VM_MRUBYC)
  file(GLOB REMOVE_MRUBY_SRCS CONFIGURE_DEPENDS
    ${PICORUBY_ROOT}/mrbgems/picoruby-mruby/ports/rp2040/*.c
  )
  list(REMOVE_ITEM SOURCE_FILES ${REMOVE_MRUBY_SRCS})
endif()

# NOTE: psg/pitchdetector cannot simply be cut by dropping their port .c
# here — their Ruby-binding src/*.c is compiled into libmruby.a and
# references the port symbols (psg_drv_*, PSG_tick_start_core1), so removing
# the ports breaks the link. They therefore stay compiled in the NS build;
# their core-1 launch will fault at runtime until the sg_launch_core1_ns
# veneer exists (phase 2). Truly excluding them needs a TZ-specific mruby
# build_config that drops the gems from the VM. See tz/README.md.

add_executable(${PROJECT_NAME}
  ${SOURCE_FILES}
)

pico_enable_stdio_usb(${PROJECT_NAME} 0)
if(PICORB_DEBUG)
  pico_enable_stdio_uart(${PROJECT_NAME} 1)
else()
  pico_enable_stdio_uart(${PROJECT_NAME} 0)
endif()

if(PICO_BOARD STREQUAL "pico" OR PICO_BOARD STREQUAL "pico_w")
  add_compile_definitions(PICO_RP2040=1)
  target_compile_definitions(${PROJECT_NAME} PRIVATE FLASH_TARGET_OFFSET=0x00140000)
elseif(PICO_BOARD STREQUAL "pico2" OR PICO_BOARD STREQUAL "pico2_w")
  add_compile_definitions(PICO_RP2350=1)
  target_compile_definitions(${PROJECT_NAME} PRIVATE FLASH_TARGET_OFFSET=0x00340000)
endif()

# Fix for pico-sdk 2.2.0: Assume core1 is safe for flash operations
# Core1 is used for PSG audio processing but doesn't access flash during BTStack operations
add_compile_definitions(PICO_FLASH_ASSUME_CORE1_SAFE=1)

set(PICORBC ${PICORUBY_ROOT}/bin/mrbc)

add_custom_target(mrbdir ALL
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/mrb
)

set(RUBY_FILES main_task)
add_dependencies(${PROJECT_NAME}
  mrbdir
  ${RUBY_FILES}
)
foreach(rb ${RUBY_FILES})
  add_custom_target(${rb}
    COMMAND
      mkdir -p ${CMAKE_BINARY_DIR}/mrb &&
      ${PICORBC} -B${rb} -o${CMAKE_BINARY_DIR}/mrb/${rb}.c ${R2P2_GEM_DIR}/mrblib/${rb}.rb
    DEPENDS ${R2P2_GEM_DIR}/mrblib/${rb}.rb
  )
endforeach(rb)

target_link_directories(${PROJECT_NAME} PRIVATE
  ${EXTRA_LIBRARY_PATH}
  ${PICORUBY_ROOT}/build/${MRUBY_CONFIG}/lib
)

pico_generate_pio_header(${PROJECT_NAME}
  ${PICORUBY_ROOT}/mrbgems/picoruby-psg/ports/rp2040/psg_drv_mcp4922_pio.pio
)

target_link_options(${PROJECT_NAME} PRIVATE -Wl,--gc-sections)

# RP2040: 4KB stack fits in SCRATCH_Y, use SDK default linker script
# RP2350: 8KB stack needs RAM, use custom linker script
if(PICO_BOARD STREQUAL "pico" OR PICO_BOARD STREQUAL "pico_w")
  set(PICORB_STACK_SIZE 0x1000) # 4KB
elseif(PICO_BOARD STREQUAL "pico2" OR PICO_BOARD STREQUAL "pico2_w")
  set(PICORB_STACK_SIZE 0x2000) # 8KB
  # The TZ build uses its own NS linker script (set in ns_build.cmake);
  # skip the default one here.
  if(NOT R2P2_TRUSTZONE)
    pico_set_linker_script(${PROJECT_NAME} ${CMAKE_CURRENT_LIST_DIR}/memmap_rp2350.ld)
  endif()
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE
  PICO_STACK_SIZE=${PICORB_STACK_SIZE}
  PICO_CORE1_STACK_SIZE=0x0800 # 2KB (in SCRATCH_X)
  PICO_HEAP_SIZE=0x0400        # 1KB
)

option(PICORUBY_PSG_MCP4922_DMA "Use DMA for PSG MCP4922 output" ON)
if(PICORUBY_PSG_MCP4922_DMA)
  target_compile_definitions(${PROJECT_NAME} PRIVATE PSG_MCP4922_DMA=1)
endif()

option(PICORUBY_PSG_PWM_DMA "Use DMA for PSG PWM output" ON)
if(PICORUBY_PSG_PWM_DMA)
  target_compile_definitions(${PROJECT_NAME} PRIVATE PSG_PWM_DMA=1)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE
  pico_stdlib
  pico_stdio
  pico_stdio_uart
  pico_rand
  tinyusb_device
  tinyusb_board
  hardware_flash
  hardware_adc
  hardware_uart
  hardware_i2c
  hardware_spi
  hardware_pwm
  pico_runtime
  pico_aon_timer
  cmsis_core      # for RP2350
  pico_multicore  # for RP2040
  hardware_claim
  hardware_pio
  hardware_dma
  mruby
)

# double-tap-reset-to-BOOTSEL: its constructor runs before main and reads
# powman_hw->chip_reset (POWMAN, Secure-only under the TZ split) -> BusFault
# from NS. Non-essential (BOOTSEL still works via the button, and the ROM
# can do double-tap via OTP BOOT_FLAGS), so drop it in the TZ build.
if(NOT R2P2_TRUSTZONE)
  target_link_libraries(${PROJECT_NAME} PRIVATE pico_bootsel_via_double_reset)
endif()

# Sleep functionality for both RP2040 and RP2350
target_link_libraries(${PROJECT_NAME} PRIVATE
  hardware_sleep
)

# RTC only for RP2040
if(PICO_BOARD STREQUAL "pico" OR PICO_BOARD STREQUAL "pico_w")
  target_link_libraries(${PROJECT_NAME} PRIVATE
    hardware_rtc
  )
endif()

if(USE_WIFI)
  if(R2P2_TRUSTZONE)
    # Poll mode under TrustZone (tz/docs/WIFI-UNDER-TZ-HANDOFF.md §2):
    # threadsafe_background drives cyw43 from a dynamically claimed spare
    # NVIC user IRQ, which would silently never fire NS unless pinned and
    # ITNS-routed. Poll mode needs no user IRQ and fits the cooperative
    # single-caller model; the net/socket gems already compile with
    # PICO_CYW43_ARCH_POLL=1 and call cyw43_arch_poll() in their wait
    # loops, and picorb_hal_idle_cpu polls from the VM idle hook. No
    # Bluetooth: btstack is not linked (BLE gems are out of the TZ config).
    target_link_libraries(${PROJECT_NAME} PRIVATE
      pico_cyw43_arch_lwip_poll
    )
  else()
    # these are used only in WiFi build
    target_link_libraries(${PROJECT_NAME} PRIVATE
      pico_cyw43_arch_lwip_threadsafe_background
      pico_btstack_ble
      pico_btstack_cyw43
    )
    target_include_directories(${PROJECT_NAME} PRIVATE
      ${PICORUBY_ROOT}/mrbgems/picoruby-ble/include
    )
  endif()
endif()

add_compile_definitions(PICORB_ALLOC_ESTALLOC=1)

if(PICORB_VM_MRUBY)
  add_compile_definitions(PICORB_VM_MRUBY=1)
  add_compile_definitions(MRB_INT64=1)
  add_compile_definitions(MRB_NO_BOXING=1)
  add_compile_definitions(MRB_32BIT=1)
  add_compile_definitions(MRB_UTF8_STRING=1)
  target_include_directories(${PROJECT_NAME} PRIVATE
    ${PICORUBY_ROOT}/mrbgems/picoruby-mruby/lib/mruby/include
  )
elseif(PICORB_VM_MRUBYC)
  add_compile_definitions(PICORB_VM_MRUBYC=1)
  target_include_directories(${PROJECT_NAME} PRIVATE
    ${PICORUBY_ROOT}/mrbgems/picoruby-mrubyc/lib/mrubyc/src
  )
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
  ${CMAKE_BINARY_DIR}/mrb
  ${R2P2_GEM_DIR}/include
  ${PICORUBY_ROOT}/include
  ${PICORUBY_ROOT}/mrbgems/mruby-compiler/lib/prism/include
  ${PICORUBY_ROOT}/mrbgems/mruby-compiler/include
  ${PICORUBY_ROOT}/build/${MRUBY_CONFIG}/include
  ${PICORUBY_ROOT}/mrbgems/picoruby-socket/include

  ${R2P2_GEM_DIR}/cmake
  ${PICO_SDK_PATH}/src/rp2_common/pico_stdio_usb/include
  ${PICO_SDK_PATH}/src/rp2_common/hardware_dma/include
  ${PICORUBY_ROOT}/mrbgems/picoruby-machine/include
  ${PICORUBY_ROOT}/mrbgems/picoruby-littlefs/lib/littlefs
  ${PICORUBY_ROOT}/build/${MRUBY_CONFIG}/mrbgems
  ${PICORUBY_ROOT}/mrbgems/picoruby-mbedtls/include
  ${PICORUBY_ROOT}/mrbgems/picoruby-mbedtls/lib/mbedtls/include
  ${PICORUBY_ROOT}/mrbgems/picoruby-mbedtls/lib/mbedtls/library
  ${PICORUBY_ROOT}/mrbgems/picoruby-net/include
  ${EXTRA_INCLUDE_DIR}
)

if(R2P2_TRUSTZONE)
  if(NOT (PICO_BOARD STREQUAL "pico2" OR PICO_BOARD STREQUAL "pico2_w"))
    message(FATAL_ERROR "R2P2_TRUSTZONE requires an RP2350 Arm board (pico2 or pico2_w)")
  endif()
  # NS runtime-init/rand/flash overrides, NS linker script, veneer implib.
  include(${R2P2_GEM_DIR}/tz/ns/ns_build.cmake)
  r2p2_apply_tz_ns(${PROJECT_NAME})
endif()

pico_add_extra_outputs(${PROJECT_NAME})

add_custom_command(
  TARGET ${PROJECT_NAME}
  POST_BUILD
  COMMAND gzip -kf ${PROJECT_NAME}.uf2
  COMMAND zip -r ${PROJECT_NAME}.uf2.zip ${PROJECT_NAME}.uf2
)
