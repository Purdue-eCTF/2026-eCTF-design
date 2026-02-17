#![no_std]
#![no_main]
#![feature(breakpoint)]

mod file;
mod message;
mod secrets;
mod util;

use argon2::{Argon2, Params};
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
    // #[cfg(debug_assertions)]
    {
        println!("panic with info: {info}");
    }

    loop {}
    // cortex_m::peripheral::SCB::sys_reset();
}

#[entry]
fn main() -> ! {
    // 8kb of memory
    // 8 passes
    const M: usize = 8;
    const SALT_SIZE: usize = 32;
    let passes = 1;
    const SALT: [u8; 32] = [
        0x9a, 0xf6, 0x17, 0xef, 0xb5, 0x51, 0xd9, 0x4b, 0xb, 0x85, 0x2e, 0x70, 0x8b, 0x56, 0x1d,
        0xc6, 0x1c, 0x92, 0xe, 0xc, 0xe0, 0x77, 0x85, 0x20, 0x6d, 0x87, 0x21, 0x33, 0x19, 0xe3,
        0x60, 0x24,
    ];
    const PWD: [u8; 32] = [
        0x9a, 0xf6, 0x17, 0xef, 0xb5, 0x51, 0xd9, 0x4b, 0xb, 0x85, 0x2e, 0x70, 0x8b, 0x56, 0x1d,
        0xc6, 0x1c, 0x92, 0xe, 0xc, 0xe0, 0x77, 0x85, 0x20, 0x6d, 0x87, 0x21, 0x33, 0x19, 0xe3,
        0x60, 0x24,
    ];
    let mut out = [0; SALT_SIZE];
    let mut blocks = [argon2::Block::new(); M];

    let mut ctx = Context::new(Peripherals::take().unwrap());
    
    print!("init");
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(M as u32, passes, 1, Some(SALT_SIZE)).unwrap(),
    );
    argon
        .hash_password_into_with_memory(&PWD, &SALT, &mut out, &mut blocks)
        .unwrap();
    println!("hashed to salt {out:?}");

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
