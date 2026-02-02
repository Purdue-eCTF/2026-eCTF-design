#![no_std]
#![no_main]

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::{
    Peripherals, Trng,
    led::Led,
    uart::{Uart, println},
};

use crate::message::{Message, Opcode};

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
        }
    }
}
