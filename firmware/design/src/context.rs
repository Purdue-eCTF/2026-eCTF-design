use bytemuck::{NoUninit, bytes_of};
use core::{
    fmt::{self, Write},
    marker::PhantomData,
    mem::size_of,
    sync::atomic::{AtomicU32, Ordering},
};
use cortex_m::peripheral::SYST;
use cortex_m_rt::exception;
use subtle::ConstantTimeEq;

use mspm0l222x_hal::{
    Peripherals,
    flash::{self, FLASH_PAGE_SIZE, FlashController},
    iomux::Iomux,
    trng::Trng,
    uart::{Uart0, Uart1},
};

use crate::{
    crypto::blake_hash,
    file::{FatTable, File},
    message::{MAX_BODY_SIZE, Message, MessagePort, Opcode},
    protocol::ProtocolError,
};
use crate::{
    salt::Salt,
    secrets::{K_AUTH_HASH, K_AUTH_SALT, T_COST_K_AUTH},
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
    ($($arg:tt)*) => ($crate::context::write_fmt(Opcode::Debug, format_args!($($arg)*)));
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
    ($($arg:tt)*) => ($crate::context::write_fmt(Opcode::Error, format_args!($($arg)*)));
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

        let magic_bytes = FLASH_MAGIC.to_le_bytes();
        for (i, word) in words
            .iter()
            // write magic bytes at the end of data
            .chain(core::iter::once(&magic_bytes))
            .enumerate()
        {
            unsafe { flash.write_word(self.location + i as u32 * 8, word)? };
        }

        Ok(())
    }

    pub(crate) fn get(&self) -> Option<&T> {
        if self.is_set() {
            Some(unsafe { &*(self.location as *const T) })
        } else {
            None
        }
    }
}

// TODO: move File/FatEntry to FlashEntry abstraction
pub(crate) struct Context {
    pub files: [FlashEntry<File>; 8],
    pub fat: FlashEntry<FatTable>,
    pub boot_salt_1: FlashEntry<Salt>,
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
        mspm0l222x_hal::timer::SysTickConfig::enable_with_reload(
            unsafe { &*(SYST::PTR as *const SYST) },
            32_000 - 1, // 1 ms timer interval
        );

        // TODO: PIN salt generation + penalty enforcement
        // TODO: check for flash write failure
        let iomux = Iomux::new(&peripherals.iomux);

        Uart0::init(&iomux, peripherals.uart0);
        println!("starting!");
        Uart1::init(&iomux, peripherals.uart1);
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

        let boot_salt_1: FlashEntry<Salt> = unsafe { FlashEntry::new(&_salt as *const u8 as u32) };
        // if salt isn't set, then the device was restarted during an operation
        if !boot_salt_1.is_set() {
            let derived = Salt::derive_boot_salt_1();
            unsafe { boot_salt_1.set(&derived).unwrap() };
        }
        // pin salt always derived
        let pin_salt = boot_salt_1.get().unwrap().derive_pin_salt();

        Self {
            files,
            fat,
            boot_salt_1,
            ram_salt: None,
            pin_salt,
        }
    }

    pub(crate) fn move_salt_to_ram(&mut self) {
        let salt = self.boot_salt_1.get().unwrap();
        self.ram_salt = Some(*salt);
        unsafe { self.boot_salt_1.erase() };
    }

    pub(crate) fn move_salt_to_flash(&mut self) {
        let Some(salt) = self.ram_salt else {
            panic!("tried to move salt to flash with no ram salt");
        };
        unsafe { self.boot_salt_1.set(&salt).unwrap() };
    }

    pub(crate) fn k_auth(&self, pin: &[u8; 6]) -> Result<[u8; 32], ProtocolError> {
        let mut k_auth = [0; 32];
        let mut input = [0; 32 + 6];
        input[..6].copy_from_slice(pin);
        input[6..].copy_from_slice(&self.pin_salt.0);
        Salt::derive_argon(&input, &mut k_auth, T_COST_K_AUTH);

        let k_auth_hash = blake_hash(&k_auth, &K_AUTH_SALT);
        if K_AUTH_HASH.ct_eq(&k_auth_hash).unwrap_u8() == 0 {
            return Err(ProtocolError::InvalidPin);
        }

        Ok(k_auth)
    }

    #[allow(static_mut_refs)]
    pub(crate) fn time(&self) -> u32 {
        // TODO: how long does it take for this to overflow? does that cause any issues?
        unsafe { TICKS.load(Ordering::Relaxed) }
    }

    #[allow(static_mut_refs)]
    pub(crate) fn reset_time(&self) {
        unsafe { TICKS.store(0, Ordering::Relaxed) }
    }
}

static mut TICKS: AtomicU32 = AtomicU32::new(0);
const CYCLES_PER_TICK: u32 = mspm0l222x_hal::SYSOSC_FREQUENCY / 10_000;
#[allow(static_mut_refs)]
#[exception]
fn SysTick() {
    // All access must be atomic, so this should be safe.
    let current = unsafe { TICKS.load(Ordering::Relaxed) };
    unsafe {
        TICKS.store(current + 1, Ordering::Relaxed);
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
            let _ = Message::write(self.2, MessagePort::UART0, &self.0[..self.1]);
            self.1 = 0;
        }
    }
}

impl Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let raw = s.as_bytes();
        let slice = &mut self.0[self.1..];
        let remaining = slice.len();

        if remaining >= raw.len() {
            slice[..raw.len()].copy_from_slice(raw);
            self.1 += raw.len();
        } else {
            // flush previously buffer bytes + `remaining` bytes from input
            slice.copy_from_slice(&raw[..remaining]);
            self.flush();

            // print or buffer the remaining bytes from input, ignoring errors
            for chunk in raw[remaining..].chunks(MAX_BODY_SIZE) {
                if chunk.len() >= MAX_BODY_SIZE {
                    let _ = Message::write(self.2, MessagePort::UART0, chunk);
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
