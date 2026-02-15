#![no_std]
#![no_main]

mod crypto;
mod message;
mod secrets;
mod view;

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use view::{FileView, ConcatView};

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
const GID_SIZE: usize = 2;
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

// TODO
fn handle_list(ctx: &mut Context) {
    // do i need to do this
    // check pin

    // - if not right pin, panic w message
    const FILE_USED_SIZE: usize = 1;
    const MAX_GUID_SIZE: usize = 2;

    // extra 8 bytes for newlines lolol
    let mut list: [u8; 4 + (MAX_GUID_SIZE + NAME_SIZE + 2) * 8] = [0u8; 4 + (MAX_GUID_SIZE + NAME_SIZE + 2) * 8];
    let mut counter: [u8; 1] = [0];

    for i in 0..8 {
        // if not in use, continue
        if ctx.files[i].contents[FILE_USED_SIZE + MAX_GUID_SIZE..FILE_USED_SIZE + MAX_GUID_SIZE + NAME_SIZE].is_empty() {
            continue;
        }
        counter[0] += 1;
            
        // index * info + newline + file slot
        let size_of_everything = NAME_SIZE + GID_SIZE + 2usize;

        // iterate through file slots (?) and retrieve metadata for each file
        // - slot, file name, group ids, newline
        // - print while iterating?

        let slot: [u8; 1] = [i as u8];
        list[(i * size_of_everything)..((i * size_of_everything) + 1usize)].copy_from_slice(&slot);

        // read guid
        // TODO is try_into needed if we know that u8 is fine?
        let name: [u8; NAME_SIZE] = ctx.files[i]
            .contents[FILE_USED_SIZE + MAX_GUID_SIZE..FILE_USED_SIZE + MAX_GUID_SIZE + NAME_SIZE]
            .try_into().unwrap();
        list[(4usize + (i * size_of_everything) + 1usize)..(4usize + (i * size_of_everything) + 1usize + NAME_SIZE)].copy_from_slice(&name);

        let gid: [u8; MAX_GUID_SIZE] = ctx.files[i]
            .contents[FILE_USED_SIZE..FILE_USED_SIZE + MAX_GUID_SIZE]
            .try_into().unwrap();
        list[(4usize + (i * size_of_everything) + 1usize + NAME_SIZE)..(4usize + (i * size_of_everything) + 1usize + NAME_SIZE + GID_SIZE)].copy_from_slice(&gid);

        let newline: [u8; 1] = [10];
        list[(4usize + (i * size_of_everything) + 1usize + NAME_SIZE + GID_SIZE)..(4usize + (i * size_of_everything) + 2usize + NAME_SIZE + GID_SIZE)].copy_from_slice(&newline);

        // guid + \t + name
    }
    list[0..1].copy_from_slice(&counter);
    let body = if list.is_empty() {"No files found.".as_bytes()} else {&list};

    // PRAYING THIS WORKS (TODO does result need to be used)
    Message::from_data(Opcode::List, body).unwrap().write();
    
    // (does metadata need to be formatted??)
}

// read file on given slot

fn handle_read(ctx: &mut Context) {
    //TODO: discover correct values
    let slot: usize = 0;
    let pk_sign: &[u8; 32] = &[0; _];
    let pk_sign = VerifyingKey::from_bytes(pk_sign).unwrap();

    let group = 0u16;
    let uuid = &ctx.fat[slot].uuid;

    //TODO: Hardcoded name length
    let name: &[u8; 32] = &[0; _];
    let file_length = ctx.fat[slot].length as usize;


    let fv = FileView::new(name, group, uuid, &ctx.files[slot].contents[..file_length]);
    let mut buf: [u8; 32 + 2 + 2 + 8192] = [0u8; _];
    let mut concat = fv.concat_bytes(&mut buf).unwrap();
    let expected_signature = Signature::from_bytes(&[0u8; 64]);

    let _ = pk_sign
        .verify(&concat.get_buf(), &expected_signature)
        .unwrap();

    //TODO: Where does this come from
    let sk_read: &[u8; 32] = &[0; _];
    let view = concat.as_view().unwrap();
    crypto::decrypt_payload_pub_combined(view.data, sk_read).unwrap();
    todo!()
}

fn handle_write(ctx: &mut Context) {
    todo!()
}

fn handle_receive(ctx: &mut Context) {
    todo!()
}

// TODO
fn handle_interrogate(ctx: &mut Context) {
    // check for right pin from host
    // - if not right pin, panic w message

    let mut groups: [u8; secrets::GROUP_KEYS.len() * GID_SIZE] = [0u8; secrets::GROUP_KEYS.len() * GID_SIZE];
    let mut group_count = 0;
    // TODO retrieve perms. if group's key is loaded into flash, add group?
    for group in secrets::GROUP_KEYS.iter().enumerate() {
        if group.1.pk_inter.0.is_empty() { continue };
        group_count += 1;
        groups[group_count * GID_SIZE..(group_count * GID_SIZE + GID_SIZE)].copy_from_slice(&group.1.group.to_ne_bytes());
    }

    // TODO replace with uart1 io. pretend Interrogate_retrieve exists pls
//    Message::from_data(Opcode::Interrogate_Retrieve, "");

    // send interrogate request alongside permissions
    // - (group id 1, group id 2 ... associated data = interrogate)
    // wait for response
    // - response can time out (<1000ms?)
    // receive response
    // read response
    // - check if header is for interrogate
    // - on failure (if somehow), panic w message
    // - on success:
    //   - decrypt data (I1)
    //   - un-concatenate data
    //   - verify that all files are associated with the right perms
    //   - print to host failure, no files, or the files
}

// should only be able to be called by handle_interrogate's request
// should be similar to handle_list
// TODO
fn receive_interrogate() {
    // check sent permissions
    // iterate through files and if match put information into a variable
    // - encI1 (pk-inter(file name, slot id, group id), pk-inter(file name, slot id, group id))
    // encrypt variable string/whatever (I1)
    // send everything back

}

fn handle_listen(ctx: &mut Context) {
    todo!()
}
