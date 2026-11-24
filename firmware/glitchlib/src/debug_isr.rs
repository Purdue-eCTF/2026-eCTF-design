//! Debug button interrupt: pressing the button drops into a UART echo shell. Backdoor, never ship.
//!
//! Keys: Ctrl-R prints the interrupted registers, Ctrl-D exits, anything else is echoed.
//!
//! INT_GROUP1 is shared with the design's own GPIO/COMP/TRNG sources, so after the debug work (if the
//! button fired) the design's original GROUP1 handler is always called.

use crate::regdump::{RegisterDump, SavedRegs, trampoline};
use crate::uart::{self, println};
use crate::timing;
use crate::vectors::{CHAIN_GROUP1, call_chain};
use crate::{hw, trigger};
use core::sync::atomic::{AtomicU32, Ordering};

pub const EXIT_BYTE: u8 = 0x04;
pub const REGS_BYTE: u8 = 0x12;

static BUTTON_MASK: AtomicU32 = AtomicU32::new(0);

pub fn init(pincm: u8, pin: u8) {
    if pin == trigger::DISABLED {
        return;
    }
    hw::connect_gpio(pincm, hw::Dir::Input, true);
    hw::enable_falling_edge_interrupt(pin);
    BUTTON_MASK.store(1 << pin, Ordering::Relaxed);
    hw::enable_group1_interrupt();
}

trampoline!(dbg_group1_entry, group1_inner);

extern "C" fn group1_inner(frame: &[u32; 8], saved: &SavedRegs) {
    let mask = BUTTON_MASK.load(Ordering::Relaxed);
    if mask != 0 && hw::pending() & mask != 0 {
        hw::clear_pending(mask);
        let dump = RegisterDump::new(frame, saved);
        echo_until_exit(&dump);
        // let the button settle, then drop anything that bounced while we were busy
        cortex_m::asm::delay(timing::cpu_hz() / 20);
        hw::clear_pending(mask);
    }
    call_chain(CHAIN_GROUP1);
}

fn echo_until_exit(dump: &RegisterDump) {
    println!("\r\n[debug] uart echo, Ctrl-R regs, Ctrl-D exit");

    loop {
        match uart::read_byte() {
            Ok(EXIT_BYTE) => break,
            Ok(REGS_BYTE) => {
                println!();
                dump.print();
            }
            Ok(b'\r') => uart::write_bytes(b"\r\n"),
            Ok(byte) => uart::write_bytes(&[byte]),
            Err(_) => {}
        }
    }
    println!("\r\n[debug] exiting");
}
