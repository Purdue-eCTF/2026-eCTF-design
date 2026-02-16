#![no_std]
#![no_main]
#![feature(breakpoint)]

mod message;
mod secrets;
mod util;

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::Peripherals;
use util::*;

use crate::message::{Message, Opcode};

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    {
        println!("panic with info: {info}");
    }

    loop {}
    // cortex_m::peripheral::SCB::sys_reset();
}

#[entry]
fn main() -> ! {
    let mut ctx = Context::new(Peripherals::take().unwrap());

    loop {
        let msg = Message::read().unwrap();
        println!("Got message {msg:?}");

        sensitive!(ctx, {
            match msg.opcode {
                Opcode::List => handle_list(&mut ctx),
                Opcode::Read => handle_read(&mut ctx),
                Opcode::Write => handle_write(&mut ctx),
                Opcode::Receive => handle_receive(&mut ctx),
                Opcode::Interrogate => handle_interrogate(&mut ctx),
                Opcode::Listen => handle_listen(&mut ctx),
                Opcode::Ack => panic!("Ack without sent message"),
                e @ (Opcode::Error | Opcode::Debug) => panic!("{e:?} should not be sent to board"),
            }
        });
    }
}

fn handle_list(ctx: &mut Context) {
    Message::send_data(Opcode::List, b"\x00\x12\x23test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
}

fn handle_read(ctx: &mut Context) {
    todo!()
}

fn handle_write(ctx: &mut Context) {
    todo!()
}

fn handle_receive(ctx: &mut Context) {
    todo!()
}

fn handle_interrogate(ctx: &mut Context) {
    todo!()
}

fn handle_listen(ctx: &mut Context) {
    todo!()
}
