//! Trigger GPIO (GPIOB pin chosen in the config) for triggered glitch tests (called from the C payload). See the original design's
//! `trigger.rs` for the rationale; the pin is a runtime value here, and the pulse is built from the
//! set/clear register addresses so no pin number is baked into the asm.

use crate::{hw, uart};
use core::sync::atomic::{AtomicU32, Ordering};

pub const DISABLED: u8 = 0xFF;

/// Number of NOPs the pin stays high for (~2 us at 32 MHz).
pub const TRIGGER_NOPS: usize = 64;

static MASK: AtomicU32 = AtomicU32::new(0);

pub fn init(pincm: u8, pin: u8) {
    if pin == DISABLED {
        return;
    }
    hw::connect_gpio(pincm, hw::Dir::Output, false);
    hw::make_output_low(pin);
    MASK.store(1 << pin, Ordering::Relaxed);
}

pub fn drive_high() {
    let m = MASK.load(Ordering::Relaxed);
    // SAFETY: GPIOB DOUTSET, write-1-to-set.
    unsafe { core::ptr::write_volatile(hw::set_register(), m) };
}

pub fn drive_low() {
    let m = MASK.load(Ordering::Relaxed);
    // SAFETY: GPIOB DOUTCLR, write-1-to-clear.
    unsafe { core::ptr::write_volatile(hw::clear_register(), m) };
}

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
            mask = in(reg) MASK.load(Ordering::Relaxed),
            set = in(reg) hw::set_register(),
            clr = in(reg) hw::clear_register(),
        );
    }
}

/// Drive the trigger low, wait for the host's go byte, raise the trigger, run the fixed sled, lower it.
/// Does nothing but the wait if the trigger is disabled.
///
/// The initial `drive_low` makes sure the pin starts low for every run, even if an earlier test left it high
/// (e.g. `dbg_trigger_high`), so the host always sees a rising edge.
#[inline(never)]
pub fn sequence() {
    drive_low();
    let _ = uart::read_byte();
    if MASK.load(Ordering::Relaxed) != 0 {
        run_fixed();
    }
}
