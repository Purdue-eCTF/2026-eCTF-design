/* Example C payload using glitchlib. Adapt: call glitch_example() from main() after the design's own setup. */
#include <stdint.h>
#include <string.h>
#include "glitchlib.h"

static volatile uint32_t secret[4] = {0x67696769, 0x67696769, 0x67696769, 0x67696769};

void glitch_example(const uint32_t input[4])
{
    /* after the design configured clocks + UART0 (and VTOR, if it sets one) */
    dbg_cfg_t cfg = dbg_cfg_default();   /* eCTF board: S2=PB21/PINCM63, trigger=PB22/PINCM64, 32 MHz */
    if (dbg_init(&cfg) != 0) {
        dbg_puts("glitchlib: VTOR not writable, vectors not hooked\r\n");
    }
    dbg_puts("ready example\r\n");

    dbg_trigger_sequence();              /* wait for host go byte, pulse trigger */

    /* ---- code under test: this is what the glitch should affect ---- */
    if (memcmp((const void *)secret, input, 16) == 0) {
        dbg_gprint("authed");            /* prints "glitch authed" every 3 s */
    }
    dbg_loop_print("done");              /* prints "done" every 3 s */
}
