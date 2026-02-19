use bytemuck::{NoUninit, bytes_of};
use core::{
    fmt::{self, Write},
    marker::PhantomData,
    mem::size_of,
};

use mspm0l222x_hal::{
    Peripherals,
    flash::{self, FLASH_PAGE_SIZE, FlashController},
    iomux::Iomux,
    trng::Trng,
    uart::Uart0,
};

use crate::salt::{self, Salt};
use crate::{
    file::{FatTable, File},
    message::{MAX_BODY_SIZE, Message, MessagePort, Opcode},
};

// TODO: glitching prevention or similar
// TODO: how badly will this hit flash? Can we rotate slots or something?
#[macro_export]
macro_rules! sensitive {
    ($context:ident, $($body:stmt)+) => {
        $context.move_salt_to_ram();
        $($body)+
        $context.move_salt_to_flash();
    };
}

/// Prints to the uart port
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::util::write_fmt(Opcode::Debug, format_args!($($arg)*)));
}

/// Prints to the uart port
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

/// Prints to the uart port
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::util::write_fmt(Opcode::Error, format_args!($($arg)*)));
}

/// Prints to the uart port
#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", format_args!($($arg)*)));
}

// TODO: automatically handle partial page writes
pub const FLASH_MAGIC: u64 = 0x7c79b307cf99d0d6;
pub struct FlashEntry<T: NoUninit> {
    location: u32,
    pages: u32,
    _marker: PhantomData<T>,
}

impl<T: NoUninit> FlashEntry<T> {
    pub(crate) unsafe fn new(location: u32) -> Self {
        // Flash entry must be sector-aligned
        assert!(
            location.is_multiple_of(FLASH_PAGE_SIZE as u32),
            "location {} is not page-aligned",
            location
        );
        // Type must be 8-byte aligned
        const {
            assert!(size_of::<T>().is_multiple_of(8));
        }

        Self {
            location,
            pages: (size_of::<T>() + size_of_val(&FLASH_MAGIC)).div_ceil(FLASH_PAGE_SIZE) as u32,
            _marker: PhantomData,
        }
    }

    pub(crate) unsafe fn erase(&self) {
        let flash = flash::flash();
        for page in 0..self.pages {
            unsafe {
                let _ = flash.erase_page(self.location + page * FLASH_PAGE_SIZE as u32);
            }
        }
    }
    pub(crate) unsafe fn set(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        let res = self.set_inner(data);
        if res.is_err() {
            // prevent partial writes
            unsafe { self.erase() };
        }

        res
    }

    pub(crate) fn is_set(&self) -> bool {
        (unsafe { *((self.location + size_of::<T>() as u32) as *const u64) }) == FLASH_MAGIC
    }

    #[inline]
    fn set_inner(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        let flash = flash::flash();

        let data = bytes_of(data);
        let (words, []): (&[[u8; 8]], _) = data.as_chunks() else {
            unreachable!()
        };

        flash.write_unprotect(self.location, self.pages * FLASH_PAGE_SIZE as u32);
        for page in 0..self.pages {
            unsafe {
                flash.erase_page(self.location + page * FLASH_PAGE_SIZE as u32)?;
            }
        }

        flash.write_unprotect(self.location, self.pages * FLASH_PAGE_SIZE as u32);

        for (i, word) in words.iter().enumerate() {
            unsafe { flash.write_word(self.location + i as u32 * 8, word)? };
        }

        Ok(())
    }
}

impl<T: NoUninit> AsRef<T> for FlashEntry<T> {
    fn as_ref(&self) -> &T {
        if !self.is_set() {
            panic!("tried to get ref to unset flash entry");
        }
        unsafe { &*(self.location as *const T) }
    }
}

// TODO: move File/FatEntry to FlashEntry abstraction
pub(crate) struct Context {
    pub files: [FlashEntry<File>; 8],
    pub fat: FlashEntry<FatTable>,
    pub salt: FlashEntry<Salt>,
    pub ram_salt: Option<Salt>,
    pub pin_salt: Salt,
}

unsafe extern "C" {
    pub static _files: u8;
    pub static _filetable: u8;
    pub static _salt: u8;
}

impl Context {
    pub(crate) fn new(peripherals: Peripherals) -> Self {
        // TODO: PIN salt generation + penalty enforcement
        // TODO: check for flash write failure
        let iomux = Iomux::new(&peripherals.iomux);

        Uart0::init(&iomux, peripherals.uart0);
        println!("starting!");
        // Uart1::init(&iomux, peripherals.uart1);
        FlashController::init(peripherals.flashctl);

        Trng::init(peripherals.trng);

        let file_size = core::mem::size_of::<File>().div_ceil(FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
        let files = unsafe {
            [
                FlashEntry::new(((&_files as *const u8).add(0 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(2 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(3 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(4 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(5 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(6 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(7 * file_size)) as u32),
            ]
        };

        let fat = unsafe { FlashEntry::new(&_filetable as *const u8 as u32) };

        let salt: FlashEntry<Salt> = unsafe { FlashEntry::new(&_salt as *const u8 as u32) };
        // if salt isn't set, then the device was restarted during an operation
        if !salt.is_set() {
            let derived = Salt::derive_boot_salt_1();
            unsafe { salt.set(&derived).unwrap() };
        }
        // pin salt always derived
        let pin_salt = salt.as_ref().derive_pin_salt();
        Self {
            files,
            fat,
            salt,
            ram_salt: None,
            pin_salt,
        }
    }

    pub(crate) fn move_salt_to_ram(&mut self) {
        let salt = self.salt.as_ref();
        self.ram_salt = Some(*salt);
        unsafe { self.salt.erase() };
    }

    pub(crate) fn move_salt_to_flash(&mut self) {
        let Some(salt) = self.ram_salt else {
            panic!("tried to move salt to flash with no ram salt");
        };
        unsafe { self.salt.set(&salt).unwrap() };
    }

    pub(crate) fn k_auth(&self, pin: &[u8; 6]) -> [u8; 32] {
        let mut k = [0; 32];
        let mut input = [0; 32 + 6];
        input[..6].copy_from_slice(pin);
        input[6..].copy_from_slice(&self.pin_salt.0);
        Salt::derive_argon(&input, &mut k, salt::T_COST_K_AUTH);
        k
    }
}

struct UartWriter([u8; MAX_BODY_SIZE], usize, Opcode);
impl UartWriter {
    fn new(opcode: Opcode) -> Self {
        Self([0; _], 0, opcode)
    }
}

impl UartWriter {
    fn flush(&mut self) {
        if self.1 != 0 {
            let _ = Message::write(Opcode::Debug, MessagePort::UART0, &self.0[..self.1]);
            self.1 = 0;
        }
    }
}

impl Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let slice = &mut self.0[self.1..];
        let remaining = slice.len();

        if remaining >= s.len() {
            slice[..s.len()].copy_from_slice(s.as_bytes());
            self.1 += s.len();
        } else {
            slice.copy_from_slice(&s.as_bytes()[..remaining]);
            self.flush();

            for chunk in s[remaining..].as_bytes().chunks(MAX_BODY_SIZE) {
                if chunk.len() >= MAX_BODY_SIZE {
                    let _ = Message::write(Opcode::Debug, MessagePort::UART0, chunk);
                } else {
                    self.1 = chunk.len();
                    self.0[..chunk.len()].copy_from_slice(chunk);
                }
            }
        }

        Ok(())
    }
}

/// Called internally by print and println macros.
///
/// Prints formatted info as debug messages.
pub fn write_fmt(opcode: Opcode, args: fmt::Arguments) {
    let mut writer = UartWriter::new(opcode);
    let _ = writer.write_fmt(args);
    writer.flush();
}
