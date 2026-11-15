//! HardFault, NMI and catch-all exception handlers. They print everything we know over UART0 and halt.
//!
//! Every line starts with `hardfault`, `nmi` or `default_handler` so it is easy to spot in the log.
//! `DefaultHandler` runs for every interrupt / exception with no handler of its own (the PAC
//! points all unhandled vectors at it), so the exception number tells which one it was.

use crate::regdump::{RegisterDump, SavedRegs, trampoline};
use mspm0l222x_hal::print;

/// On a CPU fault (HardFault is where all faults escalate on Cortex-M0+), report everything we
/// know and halt.
///
/// The M0+ has no CFSR/HFSR/BFAR/MMFAR, so the hardware does not say what kind of fault it was or
/// which address was accessed. All we get is the registers; `pc` is the faulting instruction, so
/// look it up with `addr2line`/objdump. The fault address is usually in one of the registers
/// used by that load/store.
///
/// Uses our own entry rather than `#[exception] HardFault` so r4-r11 are saved too (that macro
/// only provides the hardware-stacked frame).
trampoline!(HardFault, hardfault_inner);

extern "C" fn hardfault_inner(frame: &[u32; 8], saved: &SavedRegs) -> ! {
    let dump = RegisterDump::new(frame, saved);
    print!("hardfault ");
    dump.print_line();
    loop {}
}

trampoline!(NonMaskableInt, nmi_inner);
trampoline!(DefaultHandler, default_handler_inner);

extern "C" fn nmi_inner(frame: &[u32; 8], saved: &SavedRegs) {
    let dump = RegisterDump::new(frame, saved);
    print!("nmi ");
    dump.print_line();
    loop {}
}

extern "C" fn default_handler_inner(frame: &[u32; 8], saved: &SavedRegs) {
    let dump = RegisterDump::new(frame, saved);
    // live IPSR: which exception is running right now (the unhandled one)
    let active = cortex_m::peripheral::SCB::vect_active();
    match active {
        cortex_m::peripheral::scb::VectActive::Exception(e) => {
            print!("default_handler exception={:?} ", e)
        }
        cortex_m::peripheral::scb::VectActive::Interrupt { irqn } => {
            print!("default_handler irq={} ", irqn)
        }
        cortex_m::peripheral::scb::VectActive::ThreadMode => print!("default_handler thread? "),
    }
    dump.print_line();
    loop {}
}
