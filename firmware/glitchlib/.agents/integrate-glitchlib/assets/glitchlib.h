#ifndef GLITCHLIB_H
#define GLITCHLIB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DBG_PIN_DISABLED 0xFF

typedef struct {
    uint32_t cpu_hz;          /* core clock, used for the 3 s print delay (0 = 32 MHz) */
    uint8_t button_pincm;     /* IOMUX PINCM of the debug button; 0 = leave the pin mux alone */
    uint8_t button_pin;       /* GPIOB pin of the debug button, DBG_PIN_DISABLED = no button interrupt */
    uint8_t trigger_pincm;    /* IOMUX PINCM of the glitch trigger output; 0 = leave the pin mux alone */
    uint8_t trigger_pin;      /* GPIOB pin of the trigger, DBG_PIN_DISABLED = no trigger */
    uint8_t power_on_gpiob;   /* 1 = enable GPIOB power (no reset) in case the design has not */
    uint8_t install_vectors;  /* 1 = copy the vector table to RAM, hook GROUP1/NMI/HardFault and chain */
    uint8_t reserved[2];
} dbg_cfg_t;

/* Chain slots for dbg_set_chain(). */
enum { DBG_CHAIN_GROUP1 = 0, DBG_CHAIN_NMI = 1, DBG_CHAIN_HARDFAULT = 2 };

/* Defaults for the eCTF board: S2 = PB21/PINCM63, trigger = PB22/PINCM64, 32 MHz, hook vectors. */
dbg_cfg_t dbg_cfg_default(void);

/* Call after UART0 is configured (115200 8N1 as the design already does).
 * Returns 0 on success, -1 if VTOR is not writable (vectors not hooked: wire up dbg_*_entry by hand). */
int dbg_init(const dbg_cfg_t *cfg);

/* Manual vector hookup (install_vectors = 0): put these in the vector table, and register the handler that
 * used to be there so it still runs after the debug one. Both are real Thumb functions. */
void dbg_group1_entry(void);
void dbg_nmi_entry(void);
void dbg_hardfault_entry(void);
void dbg_set_chain(uint32_t slot, void (*handler)(void));

/* ---- UART0 output/input (the design must have configured UART0) ---- */
void dbg_write(const uint8_t *buf, size_t len);
void dbg_puts(const char *s);               /* no newline added */
int dbg_read_byte(void);                    /* blocking; -1 on framing/overrun error */
void dbg_delay_ms(uint32_t ms);

/* Print msg + "
" every 3 s, forever. */
void dbg_loop_print(const char *msg) __attribute__((noreturn));
/* Same, with a "glitch " prefix so the host can tell which branch was reached, e.g. dbg_gprint("occured"). */
void dbg_gprint(const char *msg) __attribute__((noreturn));

/* Raise/lower the trigger pin directly. */
void dbg_trigger_high(void);
void dbg_trigger_low(void);
/* Wait for the host go byte, pulse the trigger around a fixed NOP sled, return. */
void dbg_trigger_sequence(void);

#ifdef __cplusplus
}
#endif
#endif
