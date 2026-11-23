//! HardFault, NMI and catch-all exception handlers. They print everything we know over UART0 and halt.
//!
//! Every line starts with `hardfault`, `nmi` or `default_handler` so it is easy to spot in the log.
//! `DefaultHandler` runs for every interrupt / exception with no handler of its own (the PAC
//! points all unhandled vectors at it), so the exception number tells which one it was.

use crate::regdump::{RegisterDump, SavedRegs, trampoline};
use mspm0l222x_hal::mspm0l222x_pac::Sysctl;
use mspm0l222x_hal::print;

/// SYSCTL non-maskable interrupt sources, indexed by the bit they occupy in `SYSCTL_NMIRIS`.
const NMI_SOURCES: [&str; 7] = [
    "borlvl",
    "wwdt0",
    "lfclkfail",
    "flashded",
    "sramded",
    "vbatdn",
    "vbatup",
];

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

/// Snapshot SYSCTL's NMI bookkeeping before the handler parks.
///
/// `SYSCTL_NMIRIS` has one raw-status bit per source, `SYSCTL_SYSSTATUS` keeps the sticky
/// flash-ECC and BOR flags, and `SYSCTL_DEDERRADDR` is the word whose read hit a double-bit
/// error. Reading `SYSCTL_NMIIIDX` clears the selected bit in `NMIRIS`, so read it last.
///
/// Read-only SYSCTL access is safe here: the core is halted in the handler, so nothing else can
/// use these registers at the same time.
fn nmi_status() -> (u32, u32, u32, u8) {
    let sysctl = unsafe { Sysctl::steal() };
    let ris = sysctl.sysctl_nmiris().read().bits();
    let sysstatus = sysctl.sysctl_sysstatus().read().bits();
    let ded_addr = sysctl.sysctl_dederraddr().read().bits();
    let index = sysctl.sysctl_nmiiidx().read().stat().bits();
    (ris, sysstatus, ded_addr, index)
}

extern "C" fn nmi_inner(frame: &[u32; 8], saved: &SavedRegs) {
    let dump = RegisterDump::new(frame, saved);
    let (ris, sysstatus, ded_addr, index) = nmi_status();

    // `NMIIIDX` reports the winning source as 1 + its NMIRIS bit position.
    print!("nmi ris={ris:02x}");
    for (bit, name) in NMI_SOURCES.iter().enumerate() {
        if ris & (1 << bit) != 0 {
            print!(" {name}");
        }
    }
    // Sticky flags: bit 0 FLASHDED, bit 1 FLASHSEC, bits 2:3 BOR threshold, bit 4 BORLVL.
    print!(" sysstatus={sysstatus:08x}");
    if sysstatus & (1 << 0) != 0 {
        print!(" flashded");
    }
    if sysstatus & (1 << 1) != 0 {
        print!(" flashsec");
    }
    if sysstatus & (1 << 4) != 0 {
        print!(" borlvl");
    }
    print!(
        " borthr={} ded={ded_addr:08x} idx={index} ",
        (sysstatus >> 2) & 0b11
    );

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
