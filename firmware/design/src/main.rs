#![no_std]
#![no_main]
#![feature(breakpoint)]

mod file;
mod message;
mod secrets;
mod util;

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::Peripherals;
use util::*;

use crate::{
    file::File,
    message::{Message, Opcode},
};

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
    for file in &ctx.files {
        // TODO: gracefully handle this failure
        assert!(file.as_ref().state == File::EMPTY || file.as_ref().state == File::FULL);
    }

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
    let mut num_files = 0;
    let mut meta: [Option<(u8, u16, &[u8; 32])>; 8] = [None; 8];
    for (i, file) in ctx.files.iter().enumerate() {
        if file.is_set() {
            meta[num_files] = Some((i as u8, 1234, &[0; 32])); // TODO: actual GID and name
            num_files += 1;
        }
    }

    // TODO: write to buffer and send
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
