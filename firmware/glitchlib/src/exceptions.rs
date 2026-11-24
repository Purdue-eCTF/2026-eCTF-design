//! HardFault and NMI reporters. They print everything we know over UART0, then run the design's own
//! handler for the vector (if `vectors::install` found one) and finally halt.
//!
//! Lines start with `hardfault` or `nmi`. See the original design's `exceptions.rs` for the field meanings.

use crate::regdump::{RegisterDump, SavedRegs, trampoline};
use crate::uart::print;
use crate::vectors::{CHAIN_HARDFAULT, CHAIN_NMI, call_chain};
use mspm0l222x_pac::Sysctl;

const NMI_SOURCES: [&str; 7] = [
    "borlvl",
    "wwdt0",
    "lfclkfail",
    "flashded",
    "sramded",
    "vbatdn",
    "vbatup",
];

trampoline!(dbg_hardfault_entry, hardfault_inner);
trampoline!(dbg_nmi_entry, nmi_inner);

extern "C" fn hardfault_inner(frame: &[u32; 8], saved: &SavedRegs) -> ! {
    let dump = RegisterDump::new(frame, saved);
    print!("hardfault ");
    dump.print_line();
    call_chain(CHAIN_HARDFAULT);
    loop {}
}

/// Snapshot SYSCTL's NMI bookkeeping. Reading `NMIIIDX` clears the selected bit in `NMIRIS`, so it is last.
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

    print!("nmi ris={ris:02x}");
    for (bit, name) in NMI_SOURCES.iter().enumerate() {
        if ris & (1 << bit) != 0 {
            print!(" {name}");
        }
    }
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

    // NMIIIDX was read above, so the design's handler sees the bit already cleared.
    call_chain(CHAIN_NMI);
    loop {}
}
