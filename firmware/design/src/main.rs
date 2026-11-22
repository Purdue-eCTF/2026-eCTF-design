#![no_std]
#![no_main]

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use design::glitch_payloads::Payload;
use mspm0l222x_hal::{
    CorePeripherals, Peripherals, Trng, flash::FlashController, iomux::Iomux, trng, uart::Uart0,
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
        gpioa,
        gpiob,
        ..
    } = peripherals;
    Trng::init(trng_peripheral);
    unsafe {
        __stack_chk_guard = trng::trng().word() as usize;
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
    // debug_isr::init resets GPIOB, so the trigger (PB22) must be configured after it
    design::debug_isr::init(&iomux, &gpiob);
    design::trigger::init(&iomux, &gpiob);

    Payload::selected().run()
}
