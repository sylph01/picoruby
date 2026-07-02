/* R2P2 Secure monitor linker script (RP2350, TrustZone-M) — SKETCH
 *
 * Derived from pico-sdk memmap_default.ld (rp2350). Differences:
 *
 *  - Explicit MEMORY regions instead of INCLUDE "pico_flash_region.ld":
 *    the monitor owns a fixed 64 KiB at the start of flash, split into
 *    60 KiB Secure code/data and a 4 KiB Secure+NSC gateway region.
 *  - A .gnu.sgstubs output section in FLASH_NSC: GCC (-mcmse, linked with
 *    --cmse-implib) emits the SG veneers for every cmse_nonsecure_entry
 *    function here. The SAU marks exactly this 4 KiB as Secure+NSC; its
 *    address must stay fixed so NS images keep working across monitor
 *    rebuilds (also pass --in-implib=<previous implib> when relinking).
 *  - RAM is SRAM8+SRAM9 only (the two direct-mapped 4 KiB scratch banks,
 *    0x20080000..0x20081FFF). Main striped SRAM belongs to NS; the monitor
 *    may use it as boot-time scratch before the SAU is enabled, but nothing
 *    may be *linked* there. Monitor stack sits at the top of RAM_S; there
 *    is no core-1 image and no scratch_x/scratch_y sections.
 *
 * The IMAGE_DEF embedded block must carry EXE_SECURITY=S and the image is
 * signed with pico_sign_binary(); both are CMake-side concerns.
 */

MEMORY
{
    FLASH_S(rx)   : ORIGIN = 0x10000000, LENGTH = 60k
    FLASH_NSC(rx) : ORIGIN = 0x1000f000, LENGTH = 4k
    RAM_S(rwx)    : ORIGIN = 0x20080000, LENGTH = 8k
}

ENTRY(_entry_point)

SECTIONS
{
    .flash_begin : {
        __flash_binary_start = .;
    } > FLASH_S

    .text : {
        __logical_binary_start = .;
        KEEP (*(.vectors))
        KEEP (*(.binary_info_header))
        __binary_info_header_end = .;
        KEEP (*(.embedded_block))
        __embedded_block_end = .;
        KEEP (*(.reset))
        *(.init)
        *(.text*)
        *(.fini)

        . = ALIGN(4);
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(SORT(.preinit_array.*)))
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        PROVIDE_HIDDEN (__fini_array_start = .);
        *(SORT(.fini_array.*))
        *(.fini_array)
        PROVIDE_HIDDEN (__fini_array_end = .);

        *(.eh_frame*)
        . = ALIGN(4);
    } > FLASH_S

    /* XIP setup function; kept for parity with the SDK crt0. */
    .boot2 : {
        __boot2_start__ = .;
        *(.boot2)
        __boot2_end__ = .;
    } > FLASH_S

    ASSERT(__boot2_end__ - __boot2_start__ <= 256,
        "ERROR: Pico second stage bootloader must be no more than 256 bytes in size")

    .rodata : {
        *(.rodata*)
        *(.srodata*)
        . = ALIGN(4);
        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.flashdata*)))
        . = ALIGN(4);
    } > FLASH_S

    .ARM.extab : {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > FLASH_S

    __exidx_start = .;
    .ARM.exidx : {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASH_S
    __exidx_end = .;

    . = ALIGN(4);
    __binary_info_start = .;
    .binary_info : {
        KEEP(*(.binary_info.keep.*))
        *(.binary_info.*)
    } > FLASH_S
    __binary_info_end = .;
    . = ALIGN(4);

    .ram_vector_table (NOLOAD): {
        *(.ram_vector_table)
    } > RAM_S

    .uninitialized_data (NOLOAD): {
        . = ALIGN(4);
        *(.uninitialized_data*)
    } > RAM_S

    /* Unlike the default script, .data does NOT swallow leftover text and
     * rodata input sections (no RAM-resident time-critical copies): RAM_S
     * is 8 KiB total, and the monitor runs from Secure XIP. */
    .data : {
        __data_start__ = .;
        *(vtable)
        *(.time_critical*)
        *(.data*)
        *(.sdata*)
        . = ALIGN(4);
        *(.after_data.*)
        . = ALIGN(4);
        PROVIDE_HIDDEN (__mutex_array_start = .);
        KEEP(*(SORT(.mutex_array.*)))
        KEEP(*(.mutex_array))
        PROVIDE_HIDDEN (__mutex_array_end = .);
        . = ALIGN(4);
    } > RAM_S AT> FLASH_S
    PROVIDE(__data_end__ = .);

    __etext = LOADADDR(.data);

    .bss (NOLOAD) : {
        . = ALIGN(4);
        __bss_start__ = .;
        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.bss*)))
        *(COMMON)
        *(.sbss*)
        . = ALIGN(4);
        __bss_end__ = .;
    } > RAM_S

    /* No general heap: monitor-side mbedTLS uses a static workspace in .bss
     * (memory_buffer_alloc or a fixed arena). __end__ kept for libc. */
    .heap (NOLOAD): {
        __end__ = .;
        end = __end__;
        KEEP(*(.heap*))
    } > RAM_S

    .stack_dummy (NOLOAD): {
        KEEP(*(.stack*))
    } > RAM_S

    .flash_end : {
        KEEP(*(.embedded_end_block*))
        PROVIDE(__flash_binary_end = .);
    } > FLASH_S =0xaa

    /* Secure Gateway veneers — the ONLY Non-secure-callable addresses in
     * the monitor. SAU region: 0x1000f000..0x1000ffff, Secure + NSC;
     * 32-byte alignment matches SAU region granularity. Placed LAST so
     * load addresses stay monotonic (FLASH_NSC sits above everything
     * FLASH_S loads, including .data's load image) — an out-of-order LMA
     * makes ld unable to form program segments. */
    .gnu.sgstubs : ALIGN(32) {
        __sg_start = .;
        *(.gnu.sgstubs*)
        . = ALIGN(32);
        __sg_end = .;
    } > FLASH_NSC

    /* crt0's data-copy table unconditionally references the scratch-bank
     * symbols; the monitor has no scratch sections (SRAM8/9 ARE its main
     * RAM), so satisfy them with empty ranges (start == end -> 0 bytes). */
    __scratch_x_source__ = 0;
    __scratch_x_start__ = 0;
    __scratch_x_end__ = 0;
    __scratch_y_source__ = 0;
    __scratch_y_start__ = 0;
    __scratch_y_end__ = 0;

    /* Monitor stack at the top of SRAM9. Single core, Secure only. */
    __StackTop = ORIGIN(RAM_S) + LENGTH(RAM_S);
    __StackBottom = __StackTop - SIZEOF(.stack_dummy);
    PROVIDE(__stack = __StackTop);
    __HeapLimit = __StackBottom;
    __StackLimit = __StackBottom;

    PROVIDE (__heap_start = __end__);
    PROVIDE (__heap_end = __HeapLimit);

    ASSERT(__StackLimit >= __HeapLimit, "region RAM_S overflowed")

    ASSERT( __binary_info_header_end - __logical_binary_start <= 1024, "Binary info must be in first 1024 bytes of the binary")
    ASSERT( __embedded_block_end - __logical_binary_start <= 4096, "Embedded block must be in first 4096 bytes of the binary")
}
