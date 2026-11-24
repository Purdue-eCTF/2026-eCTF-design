//! Snapshot of the CPU registers at exception entry, plus a naked-asm trampoline to build one.
//!
//! The hardware only stacks r0-r3, r12, lr, pc and xpsr when an exception is taken. The
//! trampoline additionally saves r4-r11, and [`RegisterDump`] combines both with the
//! reconstructed `sp`. Used by the NMI / default handlers (`exceptions.rs`) and the debug ISR.

use crate::uart::{print, println};

/// Registers of the code that was running when the exception fired. Mirrors what an
/// `ExceptionFrame` has (r0-r3, r12, lr, pc, xpsr) plus everything it doesn't (r4-r11, sp).
#[derive(Clone, Copy, Debug)]
pub struct RegisterDump {
    /// r0..=r12
    pub r: [u32; 13],
    pub sp: u32,
    pub lr: u32,
    pub pc: u32,
    pub xpsr: u32,
}

/// Layout of what the trampoline pushes: r8-r11 then r4-r7 (lowest address first).
#[repr(C)]
pub struct SavedRegs {
    r8_r11: [u32; 4],
    r4_r7: [u32; 4],
}

impl RegisterDump {
    /// Build from the hardware-stacked frame `[r0, r1, r2, r3, r12, lr, pc, xpsr]` and the
    /// registers the trampoline saved.
    pub fn new(frame: &[u32; 8], saved: &SavedRegs) -> Self {
        let mut r = [0u32; 13];
        r[..4].copy_from_slice(&frame[..4]);
        r[4..8].copy_from_slice(&saved.r4_r7);
        r[8..12].copy_from_slice(&saved.r8_r11);
        r[12] = frame[4];
        // sp before the exception: just above the frame, plus 4 if hardware inserted alignment
        // padding (xpsr bit 9)
        let pad = (frame[7] >> 9) & 1;
        Self {
            r,
            sp: (frame.as_ptr() as u32) + 32 + pad * 4,
            lr: frame[5],
            pc: frame[6],
            xpsr: frame[7],
        }
    }

    /// Exception number that was active (IPSR in the stacked xpsr): 2 = NMI, 3 = HardFault,
    /// 11 = SVCall, 14 = PendSV, 15 = SysTick, 16+n = external interrupt n.
    ///
    /// Note: this is the exception the stacked xpsr was taken *from*. For an exception taken
    /// while another handler ran it is that handler's number, so use the live IPSR for the
    /// currently running one.
    #[allow(dead_code)]
    pub fn stacked_exception(&self) -> u32 {
        self.xpsr & 0x1ff
    }

    /// Multi-line dump of every register.
    pub fn print(&self) {
        println!("pc={:08x} lr={:08x} sp={:08x} xpsr={:08x}", self.pc, self.lr, self.sp, self.xpsr);
        for (i, chunk) in self.r.chunks(4).enumerate() {
            for (j, v) in chunk.iter().enumerate() {
                print!("r{:<2}={:08x} ", i * 4 + j, v);
            }
            println!();
        }
    }

    /// Single-line dump of every register, after `prefix`.
    pub fn print_line(&self) {
        print!("pc={:08x} lr={:08x} sp={:08x} xpsr={:08x}", self.pc, self.lr, self.sp, self.xpsr);
        for (i, v) in self.r.iter().enumerate() {
            print!(" r{}={:08x}", i, v);
        }
        println!();
    }
}

/// Define a naked exception entry `$name` which builds a `(&[u32; 8], &SavedRegs)` pair and calls
/// `extern "C" fn $inner(frame, saved)`, then returns from the exception.
///
/// Naked so no compiler prologue touches registers before they're saved. It picks MSP or PSP for
/// the frame per EXC_RETURN bit 2, saves r4-r11 and keeps the stack 8-byte aligned.
macro_rules! trampoline {
    ($name:ident, $inner:path) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "mov r0, lr",
                "movs r1, #4",
                "tst r0, r1",
                "beq 1f",
                "mrs r0, psp",
                "b 2f",
                "1:",
                "mov r0, sp",
                "2:",
                "push {{r4-r7, lr}}",
                "mov r4, r8",
                "mov r5, r9",
                "mov r6, r10",
                "mov r7, r11",
                "push {{r4-r7}}",
                "sub sp, #4",
                "mov r1, sp",
                "adds r1, #4",
                "bl {inner}",
                "add sp, #20",
                "pop {{r4-r7, pc}}",
                inner = sym $inner,
            );
        }
    };
}
pub(crate) use trampoline;
