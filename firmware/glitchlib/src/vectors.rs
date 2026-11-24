//! Hooking the design's interrupt handlers without touching its vector table in flash.
//!
//! [`install`] copies the *active* vector table (read from `SCB->VTOR`) to RAM, remembers the GROUP1, NMI and
//! HardFault entries it found as *chain* handlers, points those three entries at our trampolines and
//! switches `VTOR` to the RAM copy. Each of our handlers runs its debug logic and then calls the chained
//! design handler, if any (see [`call_chain`]).
//!
//! Handlers entered this way run in handler mode with the exception frame already stacked, so a chained
//! handler is just a plain `void f(void)` call from inside ours.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use cortex_m::peripheral::SCB;

/// 16 core exceptions + 32 external interrupts (what the eCTF design's vector table has: 192 bytes).
const ENTRIES: usize = 48;
const NMI: usize = 2;
const HARDFAULT: usize = 3;
const GROUP1: usize = 16 + 1;

/// 48 words need 256-byte alignment for VTOR. All zero, so it lives in `.bss`.
#[repr(C, align(256))]
struct Table([u32; ENTRIES]);
static mut TABLE: Table = Table([0; ENTRIES]);

pub const CHAIN_GROUP1: usize = 0;
pub const CHAIN_NMI: usize = 1;
pub const CHAIN_HARDFAULT: usize = 2;
static CHAIN: [AtomicU32; 3] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
static INSTALLED: AtomicBool = AtomicBool::new(false);

pub fn set_chain(slot: usize, handler: usize) {
    if let Some(c) = CHAIN.get(slot) {
        c.store(handler as u32, Ordering::Relaxed);
    }
}

/// Run the design's original handler for `slot`, if one was recorded.
pub fn call_chain(slot: usize) {
    let p = CHAIN[slot].load(Ordering::Relaxed);
    if p != 0 {
        // SAFETY: `p` came from a vector table entry (or dbg_set_chain), so it is a Thumb function address.
        let f: extern "C" fn() = unsafe { core::mem::transmute(p as usize) };
        f();
    }
}

/// Returns `false` if VTOR did not take the new value (no VTOR on this core): nothing is hooked then.
pub fn install() -> bool {
    if INSTALLED.load(Ordering::Relaxed) {
        return true;
    }
    cortex_m::interrupt::free(|_| unsafe {
        let scb = &*SCB::PTR;
        let old = scb.vtor.read();
        let src = old as *const u32;
        let dst = addr_of_mut!(TABLE.0) as *mut u32;
        for i in 0..ENTRIES {
            write_volatile(dst.add(i), read_volatile(src.add(i)));
        }

        let ours = [
            (GROUP1, crate::debug_isr::dbg_group1_entry as *const () as u32, CHAIN_GROUP1),
            (NMI, crate::exceptions::dbg_nmi_entry as *const () as u32, CHAIN_NMI),
            (HARDFAULT, crate::exceptions::dbg_hardfault_entry as *const () as u32, CHAIN_HARDFAULT),
        ];
        for (index, entry, slot) in ours {
            let existing = read_volatile(dst.add(index));
            if existing != entry {
                CHAIN[slot].store(existing, Ordering::Relaxed);
            }
            write_volatile(dst.add(index), entry);
        }

        cortex_m::asm::dsb();
        scb.vtor.write(dst as u32);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if scb.vtor.read() != dst as u32 {
            // VTOR is not implemented / writable; make sure nothing points at a table we aren't using
            scb.vtor.write(old);
            for slot in &CHAIN {
                slot.store(0, Ordering::Relaxed);
            }
            return false;
        }
        INSTALLED.store(true, Ordering::Relaxed);
        true
    })
}
