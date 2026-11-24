//! Trigger GPIO for the triggered glitch payloads.
//!
//! The Faultier watches this pin (EXT0/EXT1) and fires its glitch a fixed number of cycles after the
//! rising edge. [`sequence`] is the function a payload calls *before* the code under test: it waits for
//! a byte from the host (sent once the Faultier is armed), raises the pin, runs a short hardcoded NOP
//! sled, lowers the pin and returns.
//!
//! The sled is fixed on purpose. Glitch widths are now a few PIO cycles (tens of ns), so the old
//! UART-supplied loop count is gone; the host positions the pulse by sweeping its delay from the rising
//! edge instead. [`TRIGGER_NOPS`] sets the pin-high window, which the `calibrate` payload can measure.

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

/// Number of NOPs the pin stays high for.
///
/// At the 32 MHz target clock one NOP is 31.25 ns, i.e. 7.8 Faultier PIO cycles, so 64 NOPs give a
/// ~2 us (500 PIO cycle) window. An 8-NOP (250 ns) window was not seen by the edge counter or the
/// trigger input, while a DC level on the same pin was, so this gives the input/counter plenty of
/// margin. The window length does not change the glitch width; it only shifts where the code under test
/// runs, which the offset sweep accounts for.
pub const TRIGGER_NOPS: usize = 64;

/// Configure the trigger pin as a push-pull output, driven low.
///
/// This does not power on or reset GPIOB: call it *after* `debug_isr::init`, which resets the whole bank
/// (and would otherwise wipe this pin's configuration).
pub fn init(iomux: &Iomux, gpiob: &Gpiob) {
    iomux.connect_pin(TRIGGER_PINCM, 1, InOut::Output, PullMode::None);
    gpiob
        .gpiob_doutclr31_0()
        .write(|w| unsafe { w.bits(TRIGGER_MASK) });
    gpiob
        .gpiob_doeset31_0()
        .write(|w| unsafe { w.bits(TRIGGER_MASK) });
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

/// Wait for the byte the host sends after arming the Faultier.
///
/// The value is irrelevant: it only says "armed, go". A framing/overrun error is ignored; the pin still
/// pulses, so the host sees a missing result rather than a stuck target.
fn wait_for_go() {
    let _ = uart0().read_byte();
}

/// Drive the trigger pin high immediately (diagnostic / slow-toggle tests).
pub fn drive_high() {
    // SAFETY: set_register() is the GPIOB DOUTSET register, write-1-to-set.
    unsafe { core::ptr::write_volatile(set_register() as *mut u32, TRIGGER_MASK) };
}

/// Drive the trigger pin low immediately (diagnostic / slow-toggle tests).
pub fn drive_low() {
    // SAFETY: clear_register() is the GPIOB DOUTCLR register, write-1-to-clear.
    unsafe { core::ptr::write_volatile(clear_register() as *mut u32, TRIGGER_MASK) };
}

/// Raise the trigger pin, run the fixed NOP sled, lower the pin.
///
/// Both pin edges are single `str`s inside the asm, with only NOPs between them, so the pin-high time is
/// exactly [`TRIGGER_NOPS`] target cycles plus the two stores and nothing the compiler can reorder.
#[inline(never)]
fn run_fixed() {
    unsafe {
        core::arch::asm!(
            "str {mask}, [{set}]",
            ".rept {nops}",
            "nop",
            ".endr",
            "str {mask}, [{clr}]",
            nops = const TRIGGER_NOPS,
            mask = in(reg) TRIGGER_MASK,
            set = in(reg) set_register(),
            clr = in(reg) clear_register(),
        );
    }
}

/// Wait for the host's go byte, raise the trigger pin, run the fixed sled, lower the pin and return.
///
/// Call this right before the code that should be glitched; the host times its pulse from the rising
/// edge. It prints nothing and returns no value: there is no loop count to echo.
#[inline(never)]
pub fn sequence() {
    drive_low();
    wait_for_go();
    run_fixed();
}
