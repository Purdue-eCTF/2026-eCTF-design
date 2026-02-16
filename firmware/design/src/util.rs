use bytemuck::{NoUninit, bytes_of};
use core::{
    fmt::{self, Write},
    marker::PhantomData,
    ops::Index,
};

use mspm0l222x_hal::{
    Peripherals,
    flash::{self, FLASH_PAGE_SIZE, FlashController},
    iomux::Iomux,
    uart::Uart0,
};

use crate::message::{MAX_BODY_SIZE, Message, Opcode};

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
    ($($arg:tt)*) => ($crate::util::write_debug_format(format_args!($($arg)*)));
}

/// Prints to the uart port
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct File {
    pub contents: [u8; 8192],
    pub padding: [u8; 1024],
}

unsafe impl NoUninit for File {} // Generic arrays not supported by derive macro

impl File {
    pub(crate) fn addr(&self) -> u32 {
        (&self.contents as *const u8) as u32
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FatEntry {
    pub uuid: [u8; 16],
    pub length: u16,
    pub padding: u16,
    pub addr: u32,
}

impl core::fmt::Debug for FatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FatEntry")
            .field("uuid", &self.uuid)
            .field("length", &self.length)
            .field("addr", &self.addr)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FatTable {
    pub entries: [FatEntry; 8],
    _padding: [u8; FLASH_PAGE_SIZE - 8 * size_of::<FatEntry>()],
}
impl FatTable {
    pub(crate) fn new(entries: [FatEntry; 8]) -> Self {
        Self {
            entries,
            _padding: [0; _],
        }
    }
}
impl Index<usize> for FatTable {
    type Output = FatEntry;
    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}
unsafe impl NoUninit for FatTable {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Salt {
    pub salt: [u8; 32],
    pub padding: [u8; 1024 - 32],
}

unsafe impl NoUninit for Salt {}


// TODO: automatically handle partial page writes
pub struct FlashEntry<T: NoUninit> {
    location: u32,
    _marker: PhantomData<T>,
}

impl<T: NoUninit> FlashEntry<T> {
    pub(crate) unsafe fn new(location: u32) -> Self {
        // Flash entry must be sector-aligned
        assert!(
            location % (FLASH_PAGE_SIZE as u32) == 0,
            "location {} is not page-aligned",
            location
        );
        assert!(
            core::mem::size_of::<T>() % FLASH_PAGE_SIZE == 0,
            "type {:?} is not page-aligned (got {})",
            core::any::type_name::<T>(),
            core::mem::size_of::<T>()
        );

        Self {
            location,
            _marker: PhantomData,
        }
    }

    #[inline(never)]
    pub(crate) unsafe fn set(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        let flash = flash::flash();

        let data = bytes_of(data);
        let (pages, []): (&[[u8; 1024]], _) = data.as_chunks() else {
            unreachable!()
        };

        unsafe {
            for (i, page) in pages.iter().enumerate() {
                let loc = self.location + (i * FLASH_PAGE_SIZE) as u32;
                flash.rewrite_page(loc, page)?;
                flash.write_protect(loc, core::mem::size_of_val(page) as u32);
            }
        }

        Ok(())
    }
}

impl<T: NoUninit> AsRef<T> for FlashEntry<T> {
    fn as_ref(&self) -> &T {
        unsafe { &*(self.location as *const T) }
    }
}

// TODO: move File/FatEntry to FlashEntry abstraction
pub(crate) struct Context {
    pub files: [FlashEntry<File>; 8],
    pub fat: FlashEntry<FatTable>,
    pub salt: FlashEntry<Salt>,
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
        // Trng::init(peripherals.trng);

        let file_size = core::mem::size_of::<File>();
        let files = unsafe {
            [
                FlashEntry::new(((&_files as *const u8).add(0 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(1 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(2 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(3 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(4 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(5 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(6 * file_size)) as u32),
                FlashEntry::new(((&_files as *const u8).add(7 * file_size)) as u32),
            ]
        };

        let fat = unsafe { FlashEntry::new(&_filetable as *const u8 as u32) };

        let salt = unsafe { FlashEntry::new(&_salt as *const u8 as u32) };
        Self { files, fat, salt }
    }

    pub(crate) fn move_salt_to_ram(&self) {}
    pub(crate) fn move_salt_to_flash(&self) {}
}

struct UartWriter([u8; MAX_BODY_SIZE], usize);
impl UartWriter {
    fn new() -> Self {
        Self([0; _], 0)
    }
}

impl UartWriter {
    fn flush(&mut self) {
        if self.1 != 0 {
            let _ = Message::send_data(Opcode::Debug, &self.0[..self.1]);
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
                    let _ = Message::send_data(Opcode::Debug, &chunk);
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
pub fn write_debug_format(args: fmt::Arguments) {
    let mut writer = UartWriter::new();
    let _ = writer.write_fmt(args);
    writer.flush();
}
