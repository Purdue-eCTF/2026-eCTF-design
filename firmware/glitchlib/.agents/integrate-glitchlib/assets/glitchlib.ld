/* Linker script fragment: put glitchlib's code + rodata in its own output section.
 *
 * Paste inside SECTIONS {}, BEFORE the rule that collects *(.text*) / *(.rodata*), and pick the right
 * region (`> FLASH` below). Without this the library simply lands in the normal .text/.rodata, which also
 * works. Its .bss (all its state is zero-initialised) is picked up by the design's normal *(.bss*) rule.
 * Do not KEEP() it: --gc-sections should drop whatever the design does not call.
 */
    .glitch : ALIGN(4) {
        __glitch_start = .;
        *libglitchlib.a:*(.text .text.* .rodata .rodata.*)
        . = ALIGN(4);
        __glitch_end = .;
    } > FLASH
