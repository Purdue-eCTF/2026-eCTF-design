//! Trigger GPIO for the triggered glitch payloads.
//!
//! The ChipWhisperer watches this pin (wired to its `tio4`, and through a series resistor to the ADC
//! measure input while calibrating) and fires its glitch a fixed number of cycles after the rising edge.
//! [`sequence`] is the function a payload calls *before* the code under test: it reads a loop count from the
//! UART, raises the pin, runs that many iterations of a fixed loop, lowers the pin and returns. The count only
//! sets how long the pin stays high (the delay between the rising edge and the code that follows); the host
//! normally just times its glitch from the rising edge.

use mspm0l222x_hal::{
    iomux::{InOut, Iomux, PullMode},
    mspm0l222x_pac::Gpiob,
    uart::uart0,
};

/// IOMUX PINCM index of the trigger pin (PB22 is PINCM64 on the MSPM0L2228).
pub const TRIGGER_PINCM: usize = 64;
/// GPIOB pin number of the trigger pin.
pub const TRIGGER_PIN: u8 = 22;
pub const TRIGGER_MASK: u32 = 1 << TRIGGER_PIN;

/// Configure the trigger pin as a push-pull output, driven low.
///
/// This does not power on or reset GPIOB: call it *after* `debug_isr::init`, which resets the whole bank
/// (and would otherwise wipe this pin's configuration).
pub fn init(iomux: &Iomux, gpiob: &Gpiob) {
    iomux.connect_pin(TRIGGER_PINCM, 1, InOut::Output, PullMode::None);
    gpiob.gpiob_doutclr31_0().write(|w| unsafe { w.bits(TRIGGER_MASK) });
    gpiob.gpiob_doeset31_0().write(|w| unsafe { w.bits(TRIGGER_MASK) });
}

/// Address of the register that drives pins in a mask high (write-1-to-set).
pub fn set_register() -> u32 {
    // SAFETY: only the address is taken, the register is not accessed.
    unsafe { Gpiob::steal() }.gpiob_doutset31_0().as_ptr() as u32
}

/// Address of the register that drives pins in a mask low (write-1-to-clear).
pub fn clear_register() -> u32 {
    // SAFETY: only the address is taken, the register is not accessed.
    unsafe { Gpiob::steal() }.gpiob_doutclr31_0().as_ptr() as u32
}

/// Read the loop count the host sends before every triggered run: a `u32`, little-endian.
fn read_loop_count() -> u32 {
    let mut bytes = [0u8; 4];
    // a framing/overrun error leaves the count wrong, which the host sees as a mismatch in the echoed count
    let _ = uart0().read_bytes(&mut bytes);
    u32::from_le_bytes(bytes)
}

/// Raise the trigger pin, run `count` iterations of a fixed assembly loop, lower the pin, and return how
/// many iterations actually completed.
///
/// Both pin edges are single `str`s inside the asm so the pin-high time is `c0 + c1 * count` cycles with
/// nothing from the compiler in between. `count == 0` skips the loop.
#[inline(never)]
fn run_counted(count: u32) -> u32 {
    let done: u32;
    unsafe {
        core::arch::asm!(
            "str {mask}, [{set}]",
            "movs {done}, #0",
            "cmp {n}, #0",
            "beq 3f",
            "2:",
            "adds {done}, #1",
            "subs {n}, #1",
            "bne 2b",
            "3:",
            "str {mask}, [{clr}]",
            n = inout(reg) count => _,
            done = out(reg) done,
            mask = in(reg) TRIGGER_MASK,
            set = in(reg) set_register(),
            clr = in(reg) clear_register(),
        );
    }
    done
}

/// Read a loop count from the UART, raise the trigger pin, run the loop, lower the pin and return how many
/// iterations completed. Call this right before the code that should be glitched; when it returns, run that
/// code. The return value is only useful to echo back to the host (or to ignore).
#[inline(never)]
pub fn sequence() -> u32 {
    run_counted(read_loop_count())
}
