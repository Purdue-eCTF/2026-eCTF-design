#![no_std]
#![no_main]

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use design::{eprintln, println, sensitive};
use mspm0l222x_hal::{CorePeripherals, Peripherals, Trng, trng};

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
    // Startup tasks...
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

    let core_peripherals = CorePeripherals::take().unwrap();

    // Set up peripherals and derive boot salt 1/PIN salt 1
    let mut ctx = Context::new(sysctl, iomux, uart0, uart1, flashctl, core_peripherals.MPU);

    loop {
        let msg_info = Message::read_header(MessagePort::UART0).unwrap();

        sensitive!(ctx, {
            handle_any(msg_info.opcode, &mut ctx, msg_info.length as usize);
        });
    }
}
