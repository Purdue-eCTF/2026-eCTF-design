#![no_std]
#![no_main]

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

mod message;

unsafe extern "C" {
    static _stack_start: u8;
    static _boot_seed: u8;
    static _boot_salt: u8;
    static _files: u8;
    static _filetable: u8;
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
pub(crate) struct Context {
    pub files: &'static [File; 8],
    pub fat: &'static [FatEntry; 8],
    pub flash: FlashController,
}

impl Context {
    pub(crate) fn new(peripherals: Peripherals) -> Self {
        let iomux = Iomux::new(&peripherals.iomux);
        Uart::init(&iomux, peripherals.uart0);
        Led::init(&iomux, peripherals.gpioa, peripherals.gpiob);
        Trng::init(peripherals.trng);
        let files = unsafe { core::mem::transmute(&_files) };
        let fat = unsafe { core::mem::transmute(&_filetable) };
        let flash = FlashController::new(peripherals.flashctl);
        Self { files, fat, flash }
    }
}

#[entry]
fn main() -> ! {
    let context = [];
    sensitive!(context, {
        // Do something sensitive
        // TODO: implement flash
    });
    let peripherals = Peripherals::take().unwrap();
    let iomux = Iomux::new(&peripherals.iomux);
    
    
    

    let context = Context::new(Peripherals::take().unwrap());
    for i in 0..8 * 1024 {
        context
            .flash
            .write_data((&context.files[0] as *const File) as u32 + i, &0u64)
            .unwrap();
    }

    println!("{:?}", &context.files[0].contents[0..10]);

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
