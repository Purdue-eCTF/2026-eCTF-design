#![no_std]
#![no_main]

use core::panic::PanicInfo;

use cortex_m_rt::entry;
use mspm0l222x_hal::{
    Peripherals, Trng, iomux::Iomux, led::Led, uart::{Uart, println}
};

use crate::message::{Message, Opcode};

mod message;

unsafe extern "C" {
    static _stack_start: u8;
    static _boot_seed: u8;
    static _boot_salt: u8;
}

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    println!("{info}");
    cortex_m::peripheral::SCB::sys_reset();
}

const BOOT_SEED: [u8; 32] = [0; _];

macro_rules! sensitive {
    ($context:ident, $($body:stmt)+) => {
        $context.move_salt_to_ram();
        $($body)+
        $context.move_salt_to_flash();
    };
}

#[entry]
fn main() -> ! {
    let context = [];
    sensitive!(context, {
        // Do something sensitive
        // TODO: implement flash
    });
    let peripherals = Peripherals::take().unwrap();
<<<<<<< HEAD
    let iomux = Iomux::new(&peripherals.iomux);
    Uart::init(&iomux, peripherals.uart0);
    Led::init(&iomux, peripherals.gpioa, peripherals.gpiob);
    Trng::init(peripherals.trng);

    loop {
        let msg = Message::read().unwrap();
        match msg.opcode {
            Opcode::List => todo!(),
            Opcode::Read => todo!(),
            Opcode::Write => todo!(),
            Opcode::Receive => todo!(),
            Opcode::Interrogate => todo!(),
            Opcode::Listen => todo!(),
            Opcode::Ack => panic!("ACK without message"),
            e @ (Opcode::Error | Opcode::Debug) => panic!("{e:?} should not be sent to board"),
=======
    Uart::init(&peripherals.iomux, peripherals.uart0);
    Led::init(&peripherals.iomux, peripherals.gpioa, peripherals.gpiob);
    for i in 0u64.. {
        led().set(LedColor::Blue);
        println!("loop iter {i}");
        println!("stack: {}", (&raw const _stack_start) as usize);
        led().clear(LedColor::Blue);
        for _ in core::hint::black_box(0..100_000) {
            nop();
>>>>>>> 974d04e (update linker script)
        }
    }
}
