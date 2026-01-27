#![no_std]
#![no_main]

use core::panic::PanicInfo;
use cortex_m::asm::nop;
use cortex_m_rt::entry;
use mspm0l222x_hal::{
    Peripherals,
    led::{Led, LedColor, led},
    uart::{Uart, println},
};

mod message;

unsafe extern "C" {
    static _stack_start: usize;
}

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    println!("{info}");
    cortex_m::peripheral::SCB::sys_reset();
}

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take().unwrap();
    Uart::init(&peripherals.iomux, peripherals.uart0);
    Led::init(&peripherals.iomux, peripherals.gpioa, peripherals.gpiob);
    for i in 0u64.. {
        led().set(LedColor::Blue);
        println!("loop iter {i}");
        led().clear(LedColor::Blue);
        for _ in core::hint::black_box(0..100_000) {
            nop();
        }
    }

    loop {}
}
