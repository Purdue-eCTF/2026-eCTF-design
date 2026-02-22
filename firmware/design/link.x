/*
Flash layout
Offset  | Size    | Name                  | Description
0x0     | 0x6000  | Bootloader            | Reserved for the eCTF bootloader
0x6000  | 0x34000 | APP1                  | Flash region that may be used by your design however you see fit. The IVT must be loaded from the base of this region
0x3A000 | 0x400   | File Allocation Table | This page MUST store the File Allocation Table
0x3A400 | 0x5c00  | APP2                  | Flash region that may be used by your design however you see fit.
*/

__file_size = 8*(9 * 1024);

MEMORY {
    BOOTLOADER(r) : ORIGIN = 0x0, LENGTH = 0x6000
    APP1(rx) : ORIGIN = 0x6000, LENGTH = 0x34000 - __file_size
    FILES(rw) : ORIGIN = (0x3A000 - __file_size), LENGTH = __file_size
    FILETABLE(rw) : ORIGIN = 0x3A000, LENGTH = 0x400
    APP2(rw) : ORIGIN = 0x3A400, LENGTH = 0x5c00
}

ASSERT(ORIGIN(APP1) + LENGTH(APP1) <= ORIGIN(FILES), "APP1 overlaps with FILES")

INCLUDE memory.x
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
    PROVIDE(_stack_start = _ram_end);

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

        *(.text .text.*);

        /* The HardFaultTrampoline uses the `b` instruction to enter `HardFault`,
        so must be placed close to it. */
        *(.HardFaultTrampoline);
        *(.HardFault.*);

        . = ALIGN(8); /* Pad .text to the alignment to workaround overlapping load section bug in old lld */
        __etext = .;
    } > APP1

    __sidata = LOADADDR(.data);

    .files : {
        _files = .;
        /* store default contents so that flash isn't empty on boot */
        KEEP(*(.files.default));
        _efiles = .;
    } > FILES

    /* ### .bss */
    .bss (NOLOAD) : ALIGN(8)
    {
        . = ALIGN(8);
        __sbss = .;
        *(.bss .bss.*);
        *(COMMON); /* Uninitialized C statics */
        . = ALIGN(8); /* 4-byte align the end (VMA) of this section */
    } > RAM

    . = ALIGN(8);
    __ebss = .;


    /* ### .uninit */
    .uninit (NOLOAD) : ALIGN(8)
    {
        . = ALIGN(8);
        *(.uninit .uninit.*);
        . = ALIGN(8);
    } > RAM

    .got (NOLOAD) :
    {
        KEEP(*(.got .got.*));
    }

    .filetable : {
        _filetable = .;
        KEEP(*(.filetable.default));
        . = ALIGN(1024);
        _efiletable = .;
        ASSERT(_efiletable - _filetable == 0x400, "FAT section has incorrect length");
    } > FILETABLE

    .salt : {
        _salt = .;
        . += 1024;
    } > APP2

    .rodata : ALIGN(8) {
        . = ALIGN(8);
        *(.rodata .rodata.*);

        . = ALIGN(8);
    } > APP2

    .data : {
        . = ALIGN(8);
        __sdata = .;
        *(.data .data.*);
        . = ALIGN(8); /* 4-byte align the end (VMA) of this section */
        __edata = .;
    } > RAM AT>APP2

    /* ## Discarded sections */
    /DISCARD/ :
    {
        /* Unused exception related info that only wastes space */
        *(.ARM.exidx);
        *(.ARM.exidx.*);
        *(.ARM.extab.*);
    }
}
