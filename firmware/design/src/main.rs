#![no_std]
#![no_main]

mod message;
mod secrets;

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::{
    flash::FlashController,
    uart::{println, Uart},
    Peripherals,
    trng::Trng,
    iomux::Iomux,
    led::Led,
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
    const MAX_GUID_SIZE: usize = 32;
    const MAX_NAME_SIZE: usize = 64;

    // extra 8 bytes for newlines lolol
    let list: [u8; (MAX_GUID_SIZE + MAX_NAME_SIZE + 8) * 8];

    for i in 0..8 {
        // find if file slot is in use TODO check convention
        // if not in use, continue
        if ctx.files[i].contents[0] == 0 {
            continue;
        }
            
        // iterate through file slots (?) and retrieve metadata for each file
        // - file name and group ids
        // - print while iterating?

        // read guid
        // TODO is try_into needed if we know that u8 is fine?
        // TODO need to know size of guid spot to read (or is it varying?)
        let guid: [u8; MAX_GUID_SIZE] = ctx.files[i]
            .contents[FILE_USED_SIZE..FILE_USED_SIZE + MAX_GUID_SIZE]
            .try_into().unwrap();
        let name: [u8; MAX_NAME_SIZE] = ctx.files[i]
            .contents[FILE_USED_SIZE + MAX_GUID_SIZE..FILE_USED_SIZE + MAX_GUID_SIZE + MAX_NAME_SIZE]
            .try_into().unwrap();
        // TODO

        // guid + \t + name
    }
    let body = if list.is_empty() {"No files found.".as_bytes()} else {list.as_bytes()};

    // HELP
    Message::from_data(Opcode::List, body).unwrap().write();
    
    // if no more file slots and nothing's (to be) printed, panic w message
    // (does metadata need to be formatted??)
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

// TODO
fn handle_interrogate(ctx: &mut Context) {
    // check for right pin from host
    // - if not right pin, panic w message

    // TODO replace with uart1 io. pretend Interrogate_retrieve exists pls
    Message::from_data(Opcode::Interrogate_Retrieve)


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
