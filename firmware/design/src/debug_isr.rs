//! Debug interrupt: pressing the user button (S2) drops into a UART liveness check.
//!
//! The whole thing is behind the `debug-isr` feature, since it is a backdoor on the UART that
//! must not ship in the final firmware. Without the feature [`init`] is a no-op and no handler
//! is linked in.
//!
//! S2 is GPIOB.21 on the eCTF board (IOMUX PINCM63), pulled to ground when pressed, so we use the
//! internal pull-up and trigger on the falling edge. (The LP-MSPM0L2228 LaunchPad wires its S2 to
//! GPIOB.8/PINCM29 instead; change the two constants below if debugging on the LaunchPad.) On the
//! eCTF board this is also the bootloader-selection pin, so do not hold it low across a reset.
//! While the interrupt is running, every byte received on UART0 is echoed back until
//! [`EXIT_BYTE`] (Ctrl-D) is received.
//!
//! Caveats:
//! - the ISR reads UART0 itself, so it steals bytes from whatever the main loop was doing with
//!   the UART at the time. That's fine for debugging, but don't press the button mid-command.
//! - GPIOA, GPIOB, COMP0 and the TRNG all share one NVIC interrupt (`GROUP1`). Only the button
//!   is enabled here, but the TRNG health-failure interrupt is also unmasked at the TRNG, so
//!   anything we don't recognise resets the board rather than leaving an interrupt we can't
//!   clear pending forever.

use mspm0l222x_hal::{iomux::Iomux, mspm0l222x_pac::Gpiob};

#[cfg(feature = "debug-isr")]
use mspm0l222x_hal::{
    gpio::{self, Edge},
    iomux::{InOut, PullMode},
    println,
    uart::uart0,
};

/// IOMUX PINCM index of the S2 button (GPIOB.21 on the eCTF board).
#[cfg(feature = "debug-isr")]
const BUTTON_PINCM: usize = 63;
/// GPIOB pin number of the S2 button.
#[cfg(feature = "debug-isr")]
const BUTTON_PIN: u8 = 21;
#[cfg(feature = "debug-isr")]
const BUTTON_MASK: u32 = 1 << BUTTON_PIN;

/// Byte which exits the echo loop (Ctrl-D).
#[cfg(feature = "debug-isr")]
pub const EXIT_BYTE: u8 = 0x04;

/// Cycles to wait after the echo loop to let the button stop bouncing (~50ms at 32MHz).
#[cfg(feature = "debug-isr")]
const DEBOUNCE_CYCLES: u32 = 1_600_000;

/// Set up the S2 button interrupt. Does nothing unless the `debug-isr` feature is enabled.
///
/// Must be called after UART0 is initialized, and `gpiob` must not be used for anything else
/// that was already configured, since this resets the whole GPIOB bank.
#[cfg(feature = "debug-isr")]
pub fn init(iomux: &Iomux, gpiob: &Gpiob) {
    gpio::gpiob::power_on(gpiob);
    iomux.connect_pin(BUTTON_PINCM, 1, InOut::Input, PullMode::Up);
    gpio::gpiob::enable_pin_interrupt(gpiob, BUTTON_PIN, Edge::Falling);
    gpio::enable_group1_interrupt(gpio::GROUP1_DEFAULT_PRIORITY);
}

#[cfg(not(feature = "debug-isr"))]
#[inline(always)]
pub fn init(_iomux: &Iomux, _gpiob: &Gpiob) {}

/// INT_GROUP1 handler (GPIOA / GPIOB / COMP0 / TRNG). See the module docs.
#[cfg(feature = "debug-isr")]
#[unsafe(no_mangle)]
extern "C" fn GROUP1() {
    if gpio::gpiob::pending() & BUTTON_MASK == 0 {
        // not the button, and we don't know how to clear whatever it is
        cortex_m::peripheral::SCB::sys_reset();
    }

    gpio::gpiob::clear(BUTTON_MASK);

    echo_until_exit();

    // let the button settle, then drop anything that bounced while we were busy
    cortex_m::asm::delay(DEBOUNCE_CYCLES);
    gpio::gpiob::clear(BUTTON_MASK);
}

/// Echo every byte received on UART0 back to the sender until [`EXIT_BYTE`] is received.
#[cfg(feature = "debug-isr")]
fn echo_until_exit() {
    let uart = uart0();

    println!("\r\n[debug] uart echo, send Ctrl-D (0x04) to exit");

    loop {
        match uart.read_byte() {
            Ok(EXIT_BYTE) => break,
            // terminals send CR for enter, so also send an LF so the cursor goes to the next line
            Ok(b'\r') => uart.write_bytes(b"\r\n"),
            Ok(byte) => uart.write_bytes(&[byte]),
            // framing/overrun errors still pop the byte from the fifo, so just keep going
            Err(_) => {}
        }
    }

    println!("\r\n[debug] exiting");
}
