/*
Flash layout
Offset  | Size    | Name                  | Description
0x0     | 0x6000  | Bootloader            | Reserved for the eCTF bootloader
0x6000  | 0x34000 | APP1                  | Flash region that may be used by your design however you see fit. The IVT must be loaded from the base of this region
0x3A000 | 0x400   | File Allocation Table | This page MUST store the File Allocation Table
0x3A400 | 0x5c00  | APP2                  | Flash region that may be used by your design however you see fit.
*/

__file_app1_size = 6*(9 * 1024);
__file_app2_size = 2*(9 * 1024);

__data_region_size = 8192 + 64;

__mpu_min_size = 32;

INCLUDE memory.x

MEMORY {
    BOOTLOADER(r) : ORIGIN = 0x0, LENGTH = 0x6000
    APP1(rx) : ORIGIN = 0x6000, LENGTH = (0x34000 - __file_app1_size - __mpu_min_size)
    FILES_APP1(rw) : ORIGIN = (0x3A000 - __file_app1_size), LENGTH = __file_app1_size
    FILETABLE(rw) : ORIGIN = 0x3A000, LENGTH = 0x400
    FILES_APP2(rw) : ORIGIN = 0x3A400, LENGTH = __file_app2_size
    APP2(rw) : ORIGIN = (0x3A400 + __file_app2_size), LENGTH = (0x5c00 - __file_app2_size)
    DATA_REGION(rw) : ORIGIN = (ORIGIN(RAM) + LENGTH(RAM) - __data_region_size), LENGTH = __data_region_size
}

ASSERT(ORIGIN(APP1) + LENGTH(APP1) <= ORIGIN(FILES_APP1), "APP1 overlaps with FILES")

INCLUDE device.x

EXTERN(__RESET_VECTOR);
EXTERN(Reset);
ENTRY(Reset);

EXTERN(__EXCEPTIONS);

EXTERN(DefaultHandler);

PROVIDE(NonMaskableInt = DefaultHandler);
EXTERN(HardFaultTrampoline);
PROVIDE(MemoryManagement = DefaultHandler);
PROVIDE(BusFault = DefaultHandler);
PROVIDE(UsageFault = DefaultHandler);
PROVIDE(SecureFault = DefaultHandler);
PROVIDE(SVCall = DefaultHandler);
PROVIDE(DebugMonitor = DefaultHandler);
PROVIDE(PendSV = DefaultHandler);
PROVIDE(SysTick = DefaultHandler);

PROVIDE(DefaultHandler = DefaultHandler_);
PROVIDE(HardFault = HardFault_);

/* # Interrupt vectors */
EXTERN(__INTERRUPTS); /* `static` variable similar to `__EXCEPTIONS` */

/* # Pre-initialization function */
/* If the user overrides this using the `pre_init!` macro or by creating a `__pre_init` function,
   then the function this points to will be called before the RAM is initialized. */
PROVIDE(__pre_init = DefaultPreInit);

SECTIONS {
    PROVIDE(_ram_start = ORIGIN(RAM));
    PROVIDE(_ram_end = ORIGIN(RAM) + LENGTH(RAM));
    PROVIDE(_stack_start = ORIGIN(DATA_REGION));

    .vector_table ORIGIN(APP1) : {
        LONG(_stack_start & 0xFFFFFFF8);

        __vector_table = .;
        KEEP(*(.vector_table.reset_vector));
        __exceptions = .;
        KEEP(*(.vector_table.exceptions));
        __eexceptions = .;
        KEEP(*(.vector_table.interrupts));
    } > APP1

    ASSERT(SIZEOF(.vector_table) == 192, "Got wrong size for vector table")

    PROVIDE(_stext = ADDR(.vector_table) + SIZEOF(.vector_table));
    .text _stext : {
        __stext = .;

        *(.Reset);

        /* The HardFaultTrampoline uses the `b` instruction to enter `HardFault`,
        so must be placed close to it. */
        *(.HardFaultTrampoline);
        *(.HardFault.*);

        /* todo: write commit page to prevent partial flash writes */

        *(.text .text.*);

        . = ALIGN(8); /* Pad .text to the alignment to workaround overlapping load section bug in old lld */
        __etext = .;
    } > APP1

    .rodata : ALIGN(8) {
        . = ALIGN(8);
        *(.rodata .rodata.*);

        . = ALIGN(8);
    } > APP1

    __sidata = LOADADDR(.data);

    .files_app1 : {
        _files_app1 = .;
        /* store default contents so that flash isn't empty on boot */
        KEEP(*(.files_app1.default));
        _efiles_app1 = .;
    } > FILES_APP1

    .files_app2 : {
        _files_app2 = .;
        /* store default contents so that flash isn't empty on boot */
        KEEP(*(.files_app2.default));
        _efiles_app2 = .;
    } > FILES_APP2

    .salt : {
        . = ALIGN(1024);
        _salt = .;
        KEEP(*(.salt.default));
        . = ALIGN(1024);
        _esalt = .;
        ASSERT(_esalt - _salt == 1024, "boot_salt_1 section has incorrect length");
    } > APP2

    .filetable : {
        _filetable = .;
        KEEP(*(.filetable.default));
        . = ALIGN(1024);
        _efiletable = .;
        ASSERT(_efiletable - _filetable == 1024, "FAT section has incorrect length");
    } > FILETABLE

    /* stack canary at start of ram */
    .stack_canary ORIGIN(RAM) (NOLOAD) : ALIGN(8) {
        KEEP(*(.stack_canary.default));
    } > RAM

    /* ### .bss */
    .bss (NOLOAD) : ALIGN(8)
    {
        . = ALIGN(8);
        __sbss = .;
        *(.bss .bss.*);
        *(COMMON); /* Uninitialized C statics */
        . = ALIGN(8); /* 4-byte align the end (VMA) of this section */
    } > DATA_REGION

    . = ALIGN(8);
    __ebss = .;


    /* ### .uninit */
    .uninit (NOLOAD) : ALIGN(8)
    {
        . = ALIGN(8);
        *(.uninit .uninit.*);
        . = ALIGN(8);
    } > DATA_REGION

    .got (NOLOAD) :
    {
        KEEP(*(.got .got.*));
    }

    .data : {
        . = ALIGN(8);
        __sdata = .;
        *(.data .data.*);
        . = ALIGN(8); /* 4-byte align the end (VMA) of this section */
        __edata = .;
    } > DATA_REGION AT>APP2

    /* ## Discarded sections */
    /DISCARD/ :
    {
        /* Unused exception related info that only wastes space */
        *(.ARM.exidx);
        *(.ARM.exidx.*);
        *(.ARM.extab.*);
    }
}
