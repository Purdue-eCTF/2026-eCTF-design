//! Glitch test payloads. Each payload prints `ready <name>` and then runs a loop that a glitch should
//! break out of, after which it prints `glitch occured` (or payload-specific output) forever.
//!
//! The payload to run on boot is stored in a [`FlashEntry`] (on the otherwise unused file allocation table
//! page) so it persists across resets. It can be changed with the debug ISR (see `debug_isr.rs`).

use blake2::{Blake2b512, Digest as BlakeDigest};
use bytemuck::{Pod, Zeroable};
use core::{hint::black_box, time::Duration};
use ed25519_dalek::hazmat::raw_verify_prehashed;
use ed25519_dalek::{Signature, VerifyingKey};
use mspm0l222x_hal::{println, timer::Instant, uart::uart0};

use crate::flash::FlashEntry;
use crate::trigger;

/// Flash page used to persist the selected payload (the FAT page, unused in glitch builds).
const SELECTION_LOCATION: u32 = 0x3A000;

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Selection {
    index: u64,
}

fn entry() -> FlashEntry<Selection> {
    unsafe { FlashEntry::new(SELECTION_LOCATION) }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Payload {
    Loop,
    LoopCmp,
    LoopCond,
    LoopSignature,
    LoopPassword,
    TriggerPassword,
    UartLoop,
    Add,
    Triggered,
    Calibrate,
}

impl Payload {
    pub const ALL: [Payload; 10] = [
        Payload::Loop,
        Payload::LoopCmp,
        Payload::LoopCond,
        Payload::LoopSignature,
        Payload::LoopPassword,
        Payload::TriggerPassword,
        Payload::UartLoop,
        Payload::Add,
        Payload::Triggered,
        Payload::Calibrate,
    ];

    /// Payload used when nothing is saved in flash.
    pub const DEFAULT: Payload = Payload::LoopCond;

    pub const fn name(self) -> &'static str {
        match self {
            Payload::Loop => "loop",
            Payload::LoopCmp => "loop_cmp",
            Payload::LoopCond => "loop_cond",
            Payload::LoopSignature => "loop_signature",
            Payload::LoopPassword => "loop_password",
            Payload::TriggerPassword => "trigger_password",
            Payload::UartLoop => "uart_loop",
            Payload::Add => "add",
            Payload::Triggered => "triggered",
            Payload::Calibrate => "calibrate",
        }
    }

    /// Payload saved in flash, or [`Payload::DEFAULT`] if none (or an invalid one) is saved.
    pub fn selected() -> Payload {
        entry()
            .get()
            .and_then(|sel| Self::ALL.get(sel.index as usize).copied())
            .unwrap_or(Self::DEFAULT)
    }

    /// Save this payload to flash so that it is run on the next boot.
    pub fn save(self) -> Result<(), mspm0l222x_hal::HalError> {
        let index = Self::ALL.iter().position(|p| *p == self).unwrap() as u64;
        unsafe { entry().set(&Selection { index }) }
    }

    /// Print `ready <name>` and run this payload forever.
    pub fn run(self) -> ! {
        println!("ready {}", self.name());

        match self {
            Payload::Loop => glitch_loop(),
            Payload::LoopCmp => glitch_loop_cmp(),
            Payload::LoopCond => glitch_loop_cond(),
            Payload::LoopSignature => glitch_loop_signature(),
            Payload::LoopPassword => glitch_password_loop(),
            Payload::TriggerPassword => glitch_password_trigger(),
            Payload::UartLoop => glitch_uart_loop(),
            Payload::Add => glitch_add(),
            Payload::Triggered => glitch_triggered(),
            Payload::Calibrate => glitch_calibrate(),
        }
    }
}

/// Print a message (same syntax as `println!`) every 3 seconds, forever, with no prefix.
macro_rules! loop_print {
    ($($arg:tt)+) => {
        loop {
            println!($($arg)+);

            let end = Instant::now() + Duration::from_secs(3);
            while Instant::now() < end {}
        }
    };
}

/// Print `glitch <message>` (message takes the same syntax as `println!`) every 3 seconds, forever. Use it at
/// the end of a branch in a payload so the host can tell which branch was reached, e.g. `gprint!("occured")`
/// prints `glitch occured` and `gprint!("bad branch")` prints `glitch bad branch`. With no arguments it
/// prints `glitch occured`.
macro_rules! gprint {
    () => {
        gprint!("occured")
    };
    ($($arg:tt)+) => {
        loop_print!("glitch {}", format_args!($($arg)+))
    };
}

/// Call `$func` (an `extern "C" fn()`) in an infinite loop written in assembly: `bl func; b loop`.
///
/// The loop is opaque to the compiler, so code after the macro stays reachable (it could only be reached if
/// a glitch skips the `b`), and the loop itself adds no extra compares or branches in Rust. The function
/// does its own `gprint!` when it detects something. It must be `#[no_mangle]` + `#[inline(never)]`.
macro_rules! harness_loop {
    ($func:path) => {
        unsafe {
            core::arch::asm!(
                "2:",
                "bl {func}",
                "b 2b",
                func = sym $func,
                clobber_abi("C"),
            );
        }
    };
}

#[inline(never)]
fn glitch_loop() -> ! {
    unsafe {
        core::arch::asm!(
            "2:", "b 2b", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
        );
    }

    gprint!();
}

#[inline(never)]
fn glitch_loop_cmp() -> ! {
    unsafe {
        core::arch::asm!(
            "movs r0, #67", "movs r1, #69", "2:", "cmp r0, r1", "bne 2b", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
            out("r0") _,
            out("r1") _,
        );
    }

    gprint!();
}

#[inline(never)]
fn glitch_loop_cond() -> ! {
    let mut counter = black_box(0);
    while black_box(counter < 128) {
        if black_box(counter == 64) {
            counter = black_box(0);
        }

        counter += black_box(1);
    }

    gprint!();
}

#[inline(never)]
fn glitch_loop_signature() -> ! {
    // should be valid public key from docs
    let public_key_bytes = [
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();

    let data = [69, 69, 69, 69, 69, 69, 69, 69];
    let signature = [67u8; 64];

    loop {
        let mut hasher = black_box(Blake2b512::new());
        hasher.update(black_box(&data));

        let sig = black_box(Signature::from_bytes(&signature));

        if black_box(
            raw_verify_prehashed::<Blake2b512, Blake2b512>(&verifying_key, hasher, None, &sig)
                .is_ok(),
        ) {
            break;
        }
    }

    gprint!();
}

#[inline(never)]
fn glitch_password_loop() -> ! {
    harness_loop!(check_password);

    // only reachable if a glitch skipped the loop branch
    gprint!("loop");
}

#[inline(never)]
fn glitch_password_trigger() -> ! {
    let done = trigger::sequence();

    check_password();

    loop_print!("done {}", done);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn check_password() {
    let input = black_box(55u32);

    if black_box(input == 0x6767) {
        gprint!("authed");
    }
}

// this version of uart sends second uart byte instead of usinng debug isr, also special protocol
#[inline(never)]
fn glitch_uart_loop() -> ! {
    let byte_result = uart0().read_byte();

    gprint!("{:?}", byte_result);
}

// special protocol not matching loop
#[inline(never)]
fn glitch_add() -> ! {
    let mut x;
    let mut y;
    let mut total;

    loop {
        total = black_box(0);
        y = black_box(0);
        loop {
            x = black_box(0);
            loop {
                black_box(x += 1);
                black_box(total += 1);
                if black_box(x >= 1000) {
                    break;
                }
            }

            black_box(y += 1);
            black_box(total += 1);
            if black_box(y >= 1000) {
                break;
            }
        }

        println!("{}-{}-{}", black_box(total), black_box(x), black_box(y));
    }
}

/// Run the trigger sequence (see [`trigger::sequence`]), then the code under test, which is where the host's
/// glitch lands. The code under test here is a placeholder that reports the iteration count forever; replace it
/// with whatever should be glitched, or call [`trigger::sequence`] at the start of any other payload.
#[inline(never)]
fn glitch_triggered() -> ! {
    let done = trigger::sequence();

    // let a = [0, 1, 67, 69, 0, 1, 67, 69];
    // let b = [0, 0, 0, 0, 0, 0, 0, 0];

    // if black_box(black_box(a) == black_box(b)) {
    //     gprint!("correct");
    // }

    loop_print!("done {}", done);
}

/// Like [`glitch_triggered`] but repeats forever without printing in a loop, so the host can measure how long
/// the trigger pin stays high for many loop counts without resetting the board between them.
#[inline(never)]
fn glitch_calibrate() -> ! {
    loop {
        let done = trigger::sequence();
        println!("done {}", done);
    }
}
