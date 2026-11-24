---
name: integrate-glitchlib
description: Integrate firmware/glitchlib (the Rust static library with the debug button shell, HardFault/NMI register dumps, Faultier trigger pin and UART print helpers) into a C design for the MSPM0L2228 so glitch payloads can be written in C. Use when asked to add, link, wire up or debug glitchlib in a C firmware project.
---

# Integrating glitchlib into a C design

`firmware/glitchlib/` builds `libglitchlib.a`, a thumbv6m static library with no `cortex-m-rt`, no HAL, no
vector table and no `Reset` of its own. The C design keeps owning reset, clocks, UART0 setup and the vector
table. The C code only links the archive, calls `dbg_init`, and calls the helpers from its payload.

## Assets (this skill is self-contained)

Everything needed to integrate is in `assets/` next to this file; copy from there, you do not need the Rust
sources:

- `assets/libglitchlib.a`: prebuilt archive (thumbv6m, release). `firmware/glitchlib/build.sh` refreshes it.
- `assets/glitchlib.h`: the C API; read it first, it is the source of truth for the API.
- `assets/glitchlib.ld`: optional linker-script fragment for a dedicated `.glitch` section.
- `assets/example_payload.c`: a complete init + trigger + print payload to adapt.

Copy `libglitchlib.a` and `glitchlib.h` (and optionally the `.ld`) into the C project and commit them there.
Only rebuild from Rust (`firmware/glitchlib/`, see its README) if the library itself needs changing.

## 1. Get the archive

- Use `assets/libglitchlib.a`. The C design's build environment (Docker/CI) normally has no Rust nightly, so
  copy the prebuilt `.a` into the C project and commit it there; do not try to build Rust in that environment.
- Only to change the library: `firmware/glitchlib/build.sh` (needs the nightly pinned in
  `firmware/glitchlib/rust-toolchain.toml`; `PAC_PATH=<local mspm0l222x-pac checkout>` builds against a local
  PAC). It rewrites `assets/` here. The C build never rebuilds it, so re-copy after any change.

## 2. Build system changes

- Put `glitchlib.h` on the include path and `#include "glitchlib.h"`.
- Link `libglitchlib.a` **after** the object files that use it, with `-Wl,--gc-sections` (the archive is mostly
  unused weak compiler-runtime code that gc drops).
- The target must be `-mcpu=cortex-m0plus -mthumb`, soft float, same as the archive.
- The link must provide `memcpy`/`memcmp` (newlib, or the design's own). With `-nostdlib` add them.
- Optional own section: paste `assets/glitchlib.ld` into the design's linker script inside `SECTIONS`,
  before its `*(.text*)` / `*(.rodata*)` rules, and fix the `> FLASH` region name. It gives a `.glitch`
  output section (`__glitch_start` / `__glitch_end`). Skipping it is fine: the code then lands in the normal
  `.text`/`.rodata`.
- The lib's state is zero-initialised `.bss` (about 0.5 KB, including a 256-byte-aligned RAM vector table), so the
  design's normal `*(.bss*)` rule must collect it and RAM must have room.
- The Rust lib defines a `#[panic_handler]` (it spins). Do not link another Rust panic handler with it.

## 3. Call it from C

Order matters (a complete version is `assets/example_payload.c`):

```c
// 1. design sets up clocks, UART0 (115200 8N1), and its own VTOR (if it sets one)
// 2. then:
dbg_cfg_t cfg = dbg_cfg_default();   // S2 = PB21/PINCM63, trigger = PB22/PINCM64, 32 MHz, hook vectors
// adjust fields if the board/pins differ, e.g. cfg.trigger_pin = DBG_PIN_DISABLED;
if (dbg_init(&cfg) != 0) { /* VTOR not writable: vectors not hooked, see "Manual hooking" */ }

// 3. the C payload
dbg_trigger_sequence();                  // blocks for the host go byte, pulses the trigger pin
if (check(input)) dbg_gprint("authed");  // prints "glitch authed" every 3 s, never returns
dbg_loop_print("done");                  // prints "done" every 3 s, never returns
```

Helpers: `dbg_write`, `dbg_puts` (no newline), `dbg_read_byte` (-1 on error), `dbg_delay_ms`,
`dbg_trigger_high/low`. The print helpers take plain strings, so format with `snprintf` in C first.
Payloads that must stay glitchable should keep their code under test free of `dbg_*` calls between
`dbg_trigger_sequence()` and the glitched instructions.

## 4. Preconditions to verify on the design (do not assume)

- UART0 is configured and enabled before `dbg_init` / any print; the lib only pushes and pops bytes and never
  configures it. Same pins and baud the host script expects.
- `dbg_init` runs **after** whatever sets `SCB->VTOR` (the app table is at the app base, e.g. 0x6000, not 0). It
  copies the *active* table, so running earlier copies the bootloader's table at 0.
- PB21 (button; also the bootloader-select pin on the eCTF board, never hold it low across reset) and PB22
  (trigger) are not used by the design. If GPIOB might not be powered, set `cfg.power_on_gpiob = 1` (enables power, does not reset
  the bank). Use `pincm = 0` for a pin the design already muxed.
- Pin numbers and PINCM values are different on the LaunchPad (S2 = PB8/PINCM29). Set them in the config.
- If the design uses the MPU, RAM (the vector table, the lib's `.bss`) and the UART/GPIO/NVIC/SCB registers
  must remain accessible in the modes the handlers run in.
- The debug ISR steals UART0 bytes from whatever the design was doing; do not press the button mid-protocol.
- Nothing else may use INT_GROUP1 expecting to be the only handler: GROUP1 is always chained, but the design's
  handler will also run when the button fired (after it was cleared).

## 5. How handler chaining works (for debugging)

`dbg_init` (with `install_vectors = 1`) reads `SCB->VTOR`, copies the 48-word table to RAM, records the design's
GROUP1 (IRQ 1), NMI and HardFault entries as chain targets, replaces them with `dbg_group1_entry`,
`dbg_nmi_entry`, `dbg_hardfault_entry` and writes `VTOR` to the RAM copy. The flash table is never modified.
Each handler runs its debug logic and then calls the design's original handler. If the `VTOR` write does not
read back (core without VTOR) `dbg_init` returns -1, restores VTOR, and hooks nothing.

### Manual hooking (`install_vectors = 0` or the -1 case)

Put `dbg_group1_entry`, `dbg_nmi_entry`, `dbg_hardfault_entry` into the design's vector table (they are real
Thumb functions) and register the handlers they replaced:
`dbg_set_chain(DBG_CHAIN_GROUP1, old_group1); dbg_set_chain(DBG_CHAIN_NMI, ...); dbg_set_chain(DBG_CHAIN_HARDFAULT, ...);`

## 6. Verify

1. Link succeeds, `nm` shows `dbg_*` symbols and **no** `Reset`, `__RESET_VECTOR` or `__INTERRUPTS` defined by the archive.
2. Flash and boot: `dbg_init` returns 0.
3. Press the button: a `[debug] uart echo ...` banner appears; Ctrl-R dumps registers, Ctrl-D exits and the
   design continues (and its own GROUP1 interrupts still work).
4. `dbg_trigger_sequence()` waits for a byte, then PB22 pulses high for about 2 us.
5. Not yet verified on hardware at the time of writing: the VTOR switch, GROUP1 chaining and the UART shim, so
   report which of these steps actually passed.

## What is not in the lib

No payloads, no payload selection (flash / Ctrl-P / Ctrl-G), no `DefaultHandler` printer, no SysTick timer: only
busy-wait delays based on `cfg.cpu_hz`. Write payloads, and any selection logic, in C.
