# glitchlib

The glitch-testing infrastructure of `../design` (debug button shell, register-dumping HardFault/NMI handlers,
Faultier trigger pin, UART print / loop-print helpers) as a thumbv6m static library for linking into a C design.
The payloads themselves are written in C by the design.

Build (nightly pinned in `rust-toolchain.toml`): `./build.sh` -> `libglitchlib.a`
(`PAC_PATH=<local mspm0l222x-pac>` builds against a local PAC checkout).

## Using it from C

```c
#include "glitchlib.h"
// after the design has configured UART0 (the lib only pushes/pops bytes, never configures it)
dbg_cfg_t cfg = dbg_cfg_default();   // S2=PB21/PINCM63, trigger=PB22/PINCM64, 32 MHz
dbg_init(&cfg);                      // 0 ok, -1 VTOR not writable

// a C payload:
dbg_trigger_sequence();              // wait for host go byte, pulse the trigger pin
if (check_password(input)) dbg_gprint("authed");   // prints "glitch authed" every 3 s
dbg_loop_print("done");
```

Link `libglitchlib.a` with `-Wl,--gc-sections`. Optionally paste `glitchlib.ld` into the design's linker script
(before its `.text`/`.rodata` rules) to get a dedicated `.glitch` output section; `__glitch_start/_end` mark it.
All of the lib's state is zero-initialised `.bss` (about 0.5 KB, mostly the 256-byte-aligned RAM vector table).

## Handler chaining

`dbg_init` (with `install_vectors = 1`) copies the active vector table (from `SCB->VTOR`) to RAM, records the
design's GROUP1 / NMI / HardFault entries, points those at `dbg_group1_entry` / `dbg_nmi_entry` /
`dbg_hardfault_entry` and switches VTOR. Each runs its debug logic, then calls the design's original handler.
GROUP1 always chains (the lib only handles the button pin; the rest of INT_GROUP1 is the design's).
If VTOR cannot be written, `dbg_init` returns -1 and hooks nothing: use `install_vectors = 0`, put the three
`dbg_*_entry` symbols in the design's vector table and register the old handlers with `dbg_set_chain`.

## What is different from `../design`

- No `cortex-m-rt` / HAL: PAC (no `rt`) + `cortex-m` only. The HAL's UART needs `Uart0::init`, which resets the
  peripheral, and `cortex-m-rt` would add a second vector table and `Reset`. Raw-register UART/GPIO instead.
- The payloads, payload selection (flash / Ctrl-P / Ctrl-G) and the `check_password` / `pc_control` machinery are gone; write payloads in C.
- Symbols are `dbg_*`; no stack protector.
- The lib defines a `#[panic_handler]` (spins).
- GPIOB only; the pins must be free in the C design, and PB21 is the bootloader pin on the eCTF board.

## Status

Builds, and links into a stub C program with the section script (checked with `arm-none-eabi-gcc`). Not yet run
on hardware: the VTOR switch, GROUP1 chaining and the UART shim are untested.
