#![no_std]
#![no_main]

mod crypto;
mod message;
mod secrets;

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mspm0l222x_hal::{
    Peripherals,
    flash::FlashController,
    iomux::Iomux,
    led::Led,
    trng::Trng,
    uart::{Uart, println},
};

use crate::message::{Message, Opcode};

unsafe extern "C" {
    static _stack_start: u8;
    static _boot_salt: u8;
    static _files: u8;
    static _filetable: u8;
}

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    println!("{info}");
    cortex_m::peripheral::SCB::sys_reset();
}

// TODO: glitching prevention or similar
// TODO: how badly will this hit flash? Can we rotate slots or something?
macro_rules! sensitive {
    ($context:ident, $($body:stmt)+) => {
        $context.move_salt_to_ram();
        $($body)+
        $context.move_salt_to_flash();
    };
}
struct File {
    contents: [u8; 8192],
}

#[repr(C)]
struct FatEntry {
    uuid: [u8; 16],
    length: u16,
    padding: u16,
    addr: usize,
}

const NAME_SIZE: usize = 32;
const UUID_SIZE: usize = 16;
const MAX_FILE_SIZE: usize = 8192;
const SIGNATURE_SIZE: usize = 32;

#[derive(Debug)]
pub enum FileViewError {
    BufferTooSmall,
}

#[derive(Default)]
pub struct ConcatOffsets {
    pub name: usize,
    pub group: usize,
    pub uuid: usize,
    pub data: usize,
    pub end: usize,
}

pub struct FileView<'a> {
    name: &'a [u8; NAME_SIZE],
    group: u16,
    uuid: &'a [u8; UUID_SIZE],
    data: &'a [u8],
}

impl<'a> FileView<'a> {
    pub fn new(
        name: &'a [u8; NAME_SIZE],
        group: u16,
        uuid: &'a [u8; UUID_SIZE],
        data: &'a [u8],
    ) -> Self {
        Self {
            name,
            group,
            uuid,
            data,
        }
    }

    pub fn concat_bytes(&self, buf: &mut [u8]) -> Result<ConcatOffsets, FileViewError> {
        let capacity = self.calculate_concat_size();
        if buf.len() < capacity {
            return Err(FileViewError::BufferTooSmall);
        }
        let mut i = 0;
        let mut o = ConcatOffsets::default();

        buf[i..i + NAME_SIZE].copy_from_slice(self.name);
        o.name = 0;
        i += NAME_SIZE;

        buf[i..i + 2].copy_from_slice(&self.group.to_le_bytes());
        o.group = i;
        i += 2;

        buf[i..i + UUID_SIZE].copy_from_slice(self.uuid);
        o.uuid = i;
        i += UUID_SIZE;

        buf[i..i + self.data.len()].copy_from_slice(self.data);
        i += self.data.len();
        o.end = i;
        Ok(o)
    }

    fn calculate_concat_size(&self) -> usize {
        NAME_SIZE + 2 + UUID_SIZE + self.data.len()
    }
}

// TODO: move File/FatEntry to FlashEntry abstraction
pub(crate) struct Context {
    pub files: &'static [File; 8],
    pub fat: &'static [FatEntry; 8],
    pub flash: FlashController,
}

impl Context {
    pub(crate) fn new(peripherals: Peripherals) -> Self {
        // TODO: PIN salt generation + penalty enforcement
        // TODO: check for flash write failure
        let iomux = Iomux::new(&peripherals.iomux);
        Uart::init(&iomux, peripherals.uart0);
        Led::init(&iomux, peripherals.gpioa, peripherals.gpiob);
        Trng::init(peripherals.trng);
        let files = unsafe { core::mem::transmute(&_files) };
        let fat = unsafe { core::mem::transmute(&_filetable) };
        let flash = FlashController::new(peripherals.flashctl);
        Self { files, fat, flash }
    }

    pub(crate) fn move_salt_to_ram(&self) {}
    pub(crate) fn move_salt_to_flash(&self) {}
}

#[entry]
fn main() -> ! {
    let mut ctx = Context::new(Peripherals::take().unwrap());

    for i in 0..8 * 1024 {
        ctx.flash
            .write_data((&ctx.files[0] as *const File) as u32 + i, &0u64)
            .unwrap();
    }

    println!("{:?}", &ctx.files[0].contents[0..10]);

    loop {
        let msg = Message::read().unwrap();

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
    todo!()
}

// read file on given slot

fn handle_read(ctx: &mut Context) {
    //TODO: discover correct values
    let slot: usize = 0;

    let pk_sign: &[u8; 32] = &[0; _];
    let group = 0u16;
    let uuid = &ctx.fat[slot].uuid;

    //TODO: Hardcoded name length
    let name: &[u8; 32] = &[0; _];
    let signature: &[u8; 64] = &[0; _];

    let file_length = ctx.fat[slot].length as usize;

    let pk_sign_k = VerifyingKey::from_bytes(pk_sign).unwrap();

    let fv = FileView::new(name, group, uuid, &ctx.files[slot].contents[..file_length]);
    let mut vbuf: [u8; 32 + 2 + 2 + 8192] = [0u8; _];
    let offsets = fv.concat_bytes(&mut vbuf).unwrap();

    let expected_signature = Signature::from_bytes(&[0u8; 64]);

    let _ = pk_sign_k
        .verify(&vbuf[..offsets.end], &expected_signature)
        .unwrap();

    //TODO: Where does this come from

    let sk_read: &[u8; 32] = &[0; _];

    let cipher_text = &mut vbuf[offsets.data..offsets.end];
    // crypto::decrypt_payload_symmetric(cipher_text, sk_read, todo!()).unwrap();

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
