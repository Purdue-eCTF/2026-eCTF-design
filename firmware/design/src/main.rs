#![no_std]
#![no_main]

use core::{panic::PanicInfo, time::Duration};
use cortex_m_rt::entry;
use design::sensitive;
use design_macros::rand_ops;
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

    // glitch_loop();
    glitch_uart_loop();
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
