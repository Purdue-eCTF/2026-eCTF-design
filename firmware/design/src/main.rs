#![no_std]
#![no_main]

use blake2::{Blake2b512, Digest as BlakeDigest};
use core::{hint::black_box, panic::PanicInfo, time::Duration};
use cortex_m_rt::{entry, exception};
use design::sensitive;
use design_macros::rand_ops;
use ed25519_dalek::hazmat::raw_verify_prehashed;
use ed25519_dalek::{Signature, VerifyingKey};
use mspm0l222x_hal::{
    CorePeripherals, Peripherals, Trng,
    flash::FlashController,
    iomux::Iomux,
    println,
    timer::Instant,
    trng,
    uart::{Uart0, Uart1, uart0},
};

use design::{
    commands::handle_any,
    context::Context,
    message::{Message, MessagePort},
    secrets::STACK_CANARY_START_VALUE,
};

/// On panic, inform the host with the information associated with the panic and reboot the board.
#[panic_handler]
fn handle_panics(_info: &PanicInfo) -> ! {
    // if salt page is missing on reboot, error gets sent then
    cortex_m::peripheral::SCB::sys_reset();
}

/// On a CPU fault (HardFault is where all faults escalate on Cortex-M0+), report what we can and
/// reboot.
///
/// The M0+ has no CFSR/HFSR/BFAR/MMFAR, so the hardware does not say what kind of fault it was or
/// which address was accessed. All we get is the stacked frame (r0-r3, r12, lr, pc, xpsr); `pc` is
/// the faulting instruction, so look it up with `addr2line`/objdump. Fault address is usually one
/// of r0-r3 (or a register not stacked) used by that load/store.
#[exception]
unsafe fn HardFault(frame: &cortex_m_rt::ExceptionFrame) -> ! {
    let pc = frame.pc();
    println!(
        "fault pc={:08x} lr={:08x} xpsr={:08x} r0={:08x} r1={:08x} r2={:08x} r3={:08x} r12={:08x}",
        pc,
        frame.lr(),
        frame.xpsr(),
        frame.r0(),
        frame.r1(),
        frame.r2(),
        frame.r3(),
        frame.r12(),
    );

    loop {}
}

#[unsafe(link_section = ".stack_canary.default")]
#[unsafe(no_mangle)]
static mut __stack_chk_guard: usize = 0;

#[unsafe(no_mangle)]
extern "C" fn __stack_chk_fail() -> ! {
    cortex_m::peripheral::SCB::sys_reset();
}

#[entry]
fn main() -> ! {
    // Startup tasks
    let peripherals = Peripherals::take().unwrap();
    let Peripherals {
        trng: trng_peripheral,
        sysctl,
        iomux,
        uart0,
        uart1,
        flashctl,
        gpiob,
        ..
    } = peripherals;
    Trng::init(trng_peripheral);
    unsafe {
        __stack_chk_guard = trng::trng().word() as usize ^ STACK_CANARY_START_VALUE;
    }

    // rand_ops!(trng::trng());

    let core_peripherals = CorePeripherals::take().unwrap();

    // Set up peripherals and derive boot salt 1/PIN salt 1
    // let mut ctx = Context::new(
    //     sysctl,
    //     iomux,
    //     uart0,
    //     uart1,
    //     flashctl,
    //     core_peripherals.MPU,
    //     core_peripherals.SYST,
    // );

    // for glitching only do needed setup
    mspm0l222x_hal::timer::init(core_peripherals.SYST);

    let iomux = Iomux::new(&iomux);

    Uart0::init(&iomux, uart0);
    // Uart1::init(&iomux, uart1);
    FlashController::init(flashctl);
    design::debug_isr::init(&iomux, &gpiob);

    // glitch_loop();
    // glitch_loop_cmp();
    // glitch_loop_cond();
    glitch_loop_signature();
    // glitch_uart_loop();
    // glitch_add();
}

#[inline(never)]
fn glitch_loop() -> ! {
    println!("ready");

    unsafe {
        core::arch::asm!(
            "2:", "b 2b", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
        );
    }

    loop {
        println!("glitch occured");

        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {}
    }
}

#[inline(never)]
fn glitch_loop_cmp() -> ! {
    println!("ready");

    unsafe {
        core::arch::asm!(
            "movs r0, #67", "movs r1, #69", "2:", "cmp r0, r1", "bne 2b", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
            out("r0") _,
            out("r1") _,
        );
    }

    loop {
        println!("glitch occured");

        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {}
    }
}

#[inline(never)]
fn glitch_loop_cond() -> ! {
    println!("ready");

    let mut counter = black_box(0);
    while black_box(counter < 128) {
        if black_box(counter == 64) {
            counter = black_box(0);
        }

        counter += black_box(1);
    }

    loop {
        println!("glitch occured");

        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {}
    }
}

#[inline(never)]
fn glitch_loop_signature() -> ! {
    println!("ready");

    // should be valid public key from docs
    let public_key_bytes = [
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();

    let data = [69, 69, 69, 69, 69, 69, 69, 69];
    let signature = [
        67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67,
        67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67,
        67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67, 67,
    ];

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

    loop {
        println!("glitch occured");

        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {}
    }
}

#[inline(never)]
fn glitch_uart_loop() -> ! {
    println!("ready");

    let byte_result = uart0().read_byte();

    loop {
        println!("byte: {:?}", byte_result);

        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {}
    }
}

#[inline(never)]
fn glitch_add() -> ! {
    println!("ready");

    let mut x = core::hint::black_box(0);
    let mut y = core::hint::black_box(0);
    let mut total = core::hint::black_box(0);

    loop {
        total = core::hint::black_box(0);
        y = core::hint::black_box(0);
        loop {
            x = core::hint::black_box(0);
            loop {
                core::hint::black_box(x += 1);
                core::hint::black_box(total += 1);
                if core::hint::black_box(x >= 1000) {
                    break;
                }
            }

            core::hint::black_box(y += 1);
            core::hint::black_box(total += 1);
            if core::hint::black_box(y >= 1000) {
                break;
            }
        }

        println!(
            "{}-{}-{}",
            core::hint::black_box(total),
            core::hint::black_box(x),
            core::hint::black_box(y)
        );
    }
}
