/*
Flash layout
Offset  | Size    | Name                  | Description
0x0     | 0x6000  | Bootloader            | Reserved for the eCTF bootloader
0x6000  | 0x34000 | APP1                  | Flash region that may be used by your design however you see fit. The IVT must be loaded from the base of this region
0x3A000 | 0x400   | File Allocation Table | This page MUST store the File Allocation Table
0x3A400 | 0x5c00  | APP2                  | Flash region that may be used by your design however you see fit.
*/

MEMORY {
    BOOTLOADER(r) : ORIGIN = 0x0, LENGTH = 0x6000
    APP1(rwx) : ORIGIN = 0x6000, LENGTH = 0x34000
    FILETABLE(rw) : ORIGIN = 0x3A000, LENGTH = 0x400
    APP2(rwx) : ORIGIN = 0x3A400, LENGTH = 0x5c00
}

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

    .vector_table : {
        __vector_table = .;
        KEEP(*(.vector_table.reset_vector));
        __exceptions = .;
        KEEP(*(.vector_table.exceptions));
        __eexceptions = .;
        KEEP(*(.vector_table.interrupts));
    } > APP1

    .text : {
        *(.text .text.*);

        /* The HardFaultTrampoline uses the `b` instruction to enter `HardFault`,
        so must be placed close to it. */
        *(.HardFaultTrampoline);
        *(.HardFault.*);

        . = ALIGN(4); /* Pad .text to the alignment to workaround overlapping load section bug in old lld */
    } > APP1

    .rodata : ALIGN(4) {
        . = ALIGN(4);
        *(.rodata .rodata.*);

        . = ALIGN(4);
    } > APP1
    
    .data : {
        . = ALIGN(4);
        __sdata = .;
        *(.data .data.*);
        . = ALIGN(4); /* 4-byte align the end (VMA) of this section */
        __edata = .;
    } > RAM AT>APP1

    __sidata = LOADADDR(.data);

    .files : {
        _files = .;
        . += 8 * 8192;
    } > FILETABLE

    /* pad secton to 8 bytes so flashing program doesn't complain */
    .padding :
    {
        __padding = .;
        . += (8 - (__padding & 7)) & 7;
        FILL(0x00);
    } > FLASH

    /* ### .bss */
    .bss (NOLOAD) : ALIGN(4)
    {
        . = ALIGN(4);
        __sbss = .;
        *(.bss .bss.*);
        *(COMMON); /* Uninitialized C statics */
        . = ALIGN(4); /* 4-byte align the end (VMA) of this section */
    } > RAM

    . = ALIGN(4);
    __ebss = .;


    /* ### .uninit */
    .uninit (NOLOAD) : ALIGN(4)
    {
        . = ALIGN(4);
        *(.uninit .uninit.*);
        . = ALIGN(4);
    } > RAM

    .got (NOLOAD) :
    {
        KEEP(*(.got .got.*));
    }

    .filetable : {
        _filetable = .;
        . += 0x400;
    } =0x00 > FILETABLE

    /* ## Discarded sections */
    /DISCARD/ :
    {
        /* Unused exception related info that only wastes space */
        *(.ARM.exidx);
        *(.ARM.exidx.*);
        *(.ARM.extab.*);
    }
}
