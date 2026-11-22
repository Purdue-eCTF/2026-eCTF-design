//! Debug interrupt: pressing the user button (S2) drops into a UART liveness check.
//!
//! This is a backdoor on the UART that must not ship in the final firmware.
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

use crate::glitch_payloads::Payload;
use crate::regdump::{RegisterDump, SavedRegs, trampoline};
use mspm0l222x_hal::{
    iomux::Iomux,
    mspm0l222x_pac::Gpiob,
    gpio::{self, Edge},
    iomux::{InOut, PullMode},
    println,
    uart::{Uart0, uart0},
};

/// IOMUX PINCM index of the S2 button (GPIOB.21 on the eCTF board).
const BUTTON_PINCM: usize = 63;
/// GPIOB pin number of the S2 button.
const BUTTON_PIN: u8 = 21;
const BUTTON_MASK: u32 = 1 << BUTTON_PIN;

/// Byte which exits the echo loop (Ctrl-D).
pub const EXIT_BYTE: u8 = 0x04;

/// Cycles to wait after the echo loop to let the button stop bouncing (~50ms at 32MHz).
const DEBOUNCE_CYCLES: u32 = 1_600_000;

/// Set up the S2 button interrupt.
///
/// Must be called after UART0 is initialized, and `gpiob` must not be used for anything else
/// that was already configured, since this resets the whole GPIOB bank.
pub fn init(iomux: &Iomux, gpiob: &Gpiob) {
    gpio::gpiob::power_on(gpiob);
    iomux.connect_pin(BUTTON_PINCM, 1, InOut::Input, PullMode::Up);
    gpio::gpiob::enable_pin_interrupt(gpiob, BUTTON_PIN, Edge::Falling);
    gpio::enable_group1_interrupt(gpio::GROUP1_DEFAULT_PRIORITY);
}

/// Key (Ctrl-R) which prints the registers of the code that was interrupted.
pub const REGS_BYTE: u8 = 0x12;

/// Key (Ctrl-P) which selects the glitch payload; must be followed by a single digit (index into `Payload::ALL`).
pub const PAYLOAD_BYTE: u8 = 0x10;

/// Key (Ctrl-N) which prints the currently selected glitch payload as `payload <index> <name>`.
pub const GET_PAYLOAD_BYTE: u8 = 0x0E;

/// Registers captured at the most recent button press, readable after the fact.
static mut LAST_DUMP: Option<RegisterDump> = None;

trampoline!(GROUP1, group1_inner);

/// Real INT_GROUP1 handler (GPIOA / GPIOB / COMP0 / TRNG). See the module docs.
extern "C" fn group1_inner(frame: &[u32; 8], saved: &SavedRegs) {
    if gpio::gpiob::pending() & BUTTON_MASK == 0 {
        // not the button, and we don't know how to clear whatever it is
        cortex_m::peripheral::SCB::sys_reset();
    }

    gpio::gpiob::clear(BUTTON_MASK);

    let dump = RegisterDump::new(frame, saved);
    unsafe { LAST_DUMP = Some(dump) };

    echo_until_exit(&dump);

    // let the button settle, then drop anything that bounced while we were busy
    cortex_m::asm::delay(DEBOUNCE_CYCLES);
    gpio::gpiob::clear(BUTTON_MASK);
}

/// Echo every byte received on UART0 back to the sender until [`EXIT_BYTE`] is received.
fn echo_until_exit(dump: &RegisterDump) {
    let uart = uart0();

    println!("\r\n[debug] uart echo, Ctrl-R prints registers, Ctrl-P <digit> selects glitch payload, Ctrl-N prints it, Ctrl-D exits");

    loop {
        match uart.read_byte() {
            Ok(EXIT_BYTE) => break,
            Ok(REGS_BYTE) => {
                println!();
                dump.print();
            }
            Ok(PAYLOAD_BYTE) => select_payload(uart),
            Ok(GET_PAYLOAD_BYTE) => {
                let current = Payload::selected();
                let index = Payload::ALL.iter().position(|p| *p == current).unwrap();
                println!("payload {} {}", index, current.name());
            }
            // terminals send CR for enter, so also send an LF so the cursor goes to the next line
            Ok(b'\r') => uart.write_bytes(b"\r\n"),
            Ok(byte) => uart.write_bytes(&[byte]),
            // framing/overrun errors still pop the byte from the fifo, so just keep going
            Err(_) => {}
        }
    }

    println!("\r\n[debug] exiting");
}

/// Read one digit right after [`PAYLOAD_BYTE`] (index into [`Payload::ALL`]), save that payload to flash and
/// reset so it runs immediately. Meant to be driven by a script: send `0x10` then e.g. `b"2"`.
fn select_payload(uart: &Uart0) {
    let payload = uart
        .read_byte()
        .ok()
        .and_then(|b| (b as char).to_digit(10))
        .and_then(|i| Payload::ALL.get(i as usize));

    let Some(payload) = payload else {
        println!("[debug] bad payload");
        return;
    };

    match payload.save() {
        Ok(()) => {
            println!("[debug] saved {}", payload.name());
            // let the message drain before resetting
            cortex_m::asm::delay(DEBOUNCE_CYCLES);
            cortex_m::peripheral::SCB::sys_reset();
        }
        Err(e) => println!("[debug] flash write failed: {}", e),
    }
}
