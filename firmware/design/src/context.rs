use common::SymmetricKey;
use core::{
    fmt::{self, Write},
    sync::atomic::{AtomicU32, Ordering},
};
use cortex_m::peripheral::SYST;
use cortex_m_rt::exception;
use mspm0l222x_hal::mpu::{MemoryCacheType, MpuPerms, MpuRegionSize};
use subtle::ConstantTimeEq;

use mspm0l222x_hal::{
    flash::{FLASH_PAGE_SIZE, FlashController},
    iomux::Iomux,
    mpu::Mpu,
    uart::{Uart0, Uart1},
};

use crate::{
    crypto::blake_hash,
    file::{FatEntry, FatTable, File, FileSlot},
    flash::FlashEntry,
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

// TODO: No prints in final design
/// Prints to the uart port
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::context::write_fmt($crate::message::Opcode::Debug, format_args!($($arg)*)));
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
    ($($arg:tt)*) => ($crate::context::write_fmt($crate::message::Opcode::Error, format_args!($($arg)*)));
}

/// Prints to the uart port
#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", format_args!($($arg)*)));
}

/// The Context contains abstracted access to the flash, including the files,
/// FAT table, and the salts (boot salt 1, ram salt, and pin salt)
pub struct Context {
    pub files: [FlashEntry<File>; 8],
    pub fat: FlashEntry<FatTable>,
    pub boot_salt_1: FlashEntry<Salt>,
    pub ram_salt: Option<Salt>,
    pub pin_salt: Salt,
}

unsafe extern "C" {
    pub static _files_app1: u8;
    pub static _files_app2: u8;
    pub static _filetable: u8;
    pub static _salt: u8;
}

impl Context {
    /// Initialize and generate a context object based on the current state of the flash.
    pub fn new(
        sysctl: mspm0l222x_hal::mspm0l222x_pac::Sysctl,
        iomux: mspm0l222x_hal::mspm0l222x_pac::Iomux,
        uart0: mspm0l222x_hal::mspm0l222x_pac::Uart0,
        uart1: mspm0l222x_hal::mspm0l222x_pac::Uart1,
        flashctl: mspm0l222x_hal::mspm0l222x_pac::Flashctl,
        mpu_regs: cortex_m::peripheral::MPU,
    ) -> Self {
        // entire ram not executable
        Mpu::sram_rw_boundary(&sysctl, 0x7fff).expect("failed to set sram rw boundary");

        let mut mpu = Mpu::new(mpu_regs);
        setup_mpu_mappings(&mut mpu);

        mspm0l222x_hal::timer::SysTickConfig::enable_with_reload(
            unsafe { &*(SYST::PTR as *const SYST) },
            32_000 - 1, // 1 ms timer interval
        );

        let iomux = Iomux::new(&iomux);

        Uart0::init(&iomux, uart0);
        Uart1::init(&iomux, uart1);
        FlashController::init(flashctl);

        // protect all flash except for FlashEntry-s
        let flash = mspm0l222x_hal::flash::flash();
        flash.write_protect(0, 256 * FLASH_PAGE_SIZE as u32);

        // Create/initialize all 8 flash entries
        let file_size =
            core::mem::size_of::<FileSlot>().div_ceil(FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
        let files = unsafe {
            [
                FlashEntry::new(((&_files_app1 as *const u8).add(0 * file_size)) as u32),
                FlashEntry::new(((&_files_app1 as *const u8).add(1 * file_size)) as u32),
                FlashEntry::new(((&_files_app1 as *const u8).add(2 * file_size)) as u32),
                FlashEntry::new(((&_files_app1 as *const u8).add(3 * file_size)) as u32),
                FlashEntry::new(((&_files_app1 as *const u8).add(4 * file_size)) as u32),
                FlashEntry::new(((&_files_app1 as *const u8).add(5 * file_size)) as u32),
                FlashEntry::new(((&_files_app2 as *const u8).add(0 * file_size)) as u32),
                FlashEntry::new(((&_files_app2 as *const u8).add(1 * file_size)) as u32),
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

    /// Move the salt from flash to ram and delete it from flash
    /// to prevent circumventing boot penalty
    pub fn move_salt_to_ram(&mut self) {
        let salt = self.boot_salt_1.get().unwrap();
        self.ram_salt = Some(*salt);
        unsafe { self.boot_salt_1.erase() };
    }

    /// Move the salt from ram to flash so that
    /// salt won't be erased on reboot
    pub fn move_salt_to_flash(&mut self) {
        let Some(salt) = self.ram_salt else {
            panic!("tried to move salt to flash with no ram salt");
        };
        unsafe { self.boot_salt_1.set(&salt).unwrap() };
        self.ram_salt = None;
    }

    #[inline(never)]
    pub fn k_auth(&self, pin: &[u8; 6]) -> Result<SymmetricKey, ProtocolError> {
        let mut k_auth = [0; 32];
        let mut input = [0; 32 + 6];
        input[..6].copy_from_slice(pin);
        input[6..].copy_from_slice(&self.pin_salt.0);

        Salt::derive_argon(&input, &mut k_auth, T_COST_K_AUTH);

        // confirm k_auth is valid
        let k_auth_hash = blake_hash(&k_auth, &K_AUTH_SALT);
        if !bool::from(K_AUTH_HASH.ct_eq(&k_auth_hash)) {
            return Err(ProtocolError::InvalidPin);
        }

        Ok(SymmetricKey(k_auth))
    }

    pub fn rebuild_fat(&self, k_auth: &SymmetricKey) -> Result<(), ProtocolError> {
        let mut entries = [FatEntry::empty(); 8];
        for (i, file) in self.files.iter().enumerate() {
            if let Some(file) = file.get() {
                entries[i] = file.to_fat(k_auth)?;
            }
        }

        unsafe {
            self.fat
                .set(&FatTable { entries })
                .map_err(|_| ProtocolError::StorageFailure)?;
        }

        Ok(())
    }

    /// TODO Retrieve the TICK timer's current value (in ticks) .
    #[allow(static_mut_refs)]
    pub fn time(&self) -> u32 {
        unsafe { TICKS.load(Ordering::Relaxed) }
    }

    /// Reset TICK timer's value to 0.
    #[allow(static_mut_refs)]
    pub fn reset_time(&self) {
        unsafe { TICKS.store(0, Ordering::Relaxed) }
    }
}

const MPU_MIN_SIZE: usize = 32;

/// Add a guard to prevent access to a region of memory.
unsafe fn add_mpu_guard(mpu: &mut Mpu, index: u32, address: u32) {
    unsafe {
        mpu.set_region(
            index,
            address,
            MpuRegionSize::Bytes32,
            0,
            MpuPerms {
                read: false,
                write: false,
                execute: false,
            },
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();
    }
}

/// Setup the MPU mappings for the board.
fn setup_mpu_mappings(mpu: &mut Mpu) {
    // TODO: remove this check
    // only added because mpu on qemu does not work
    if !mpu.is_available() {
        return;
    }

    unsafe {
        // flash readable
        mpu.set_region(
            0,
            0x0,
            MpuRegionSize::KibiByte256,
            0,
            MpuPerms {
                read: true,
                write: false,
                execute: false,
            },
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();

        // approximate region with code is executable
        // make sure not to overlap files
        // TODO: possible reduce to just a whole 128 kibibyte region, text might fit, make a bit bigger for now
        // disable the 3 highest regions
        mpu.set_region(
            1,
            0x0,
            MpuRegionSize::KibiByte256,
            0b11100000,
            MpuPerms {
                read: true,
                write: false,
                execute: true,
            },
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();

        // ram read write
        mpu.set_region(
            2,
            0x2020_0000,
            MpuRegionSize::KibiByte32,
            0,
            MpuPerms {
                read: true,
                write: true,
                execute: false,
            },
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();

        // mmio read write
        mpu.set_region(
            3,
            0x4000_0000,
            MpuRegionSize::MibiByte512,
            0,
            MpuPerms {
                read: true,
                write: true,
                execute: false,
            },
            // last year, we used strongly ordered for peripheral memory
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();

        // make stack canary read only
        mpu.set_region(
            4,
            0x2020_0000,
            MpuRegionSize::Bytes32,
            0,
            MpuPerms {
                read: true,
                write: false,
                execute: false,
            },
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();

        // first guard: stop flashcat type attack reading out file data
        let files_guard = (&_files_app1 as *const u8 as usize) - MPU_MIN_SIZE;
        add_mpu_guard(mpu, 5, files_guard as u32);

        // set FAT as no RWX, because we regenerate every time from file contents
        // and flash doesn't hit the memory system
        mpu.set_region(
            6,
            &_filetable as *const u8 as u32,
            MpuRegionSize::KibiByte1,
            0,
            MpuPerms {
                read: true,
                write: false,
                execute: false,
            },
            MemoryCacheType::StronglyOrdered,
        )
        .unwrap();

        // mpu guard before secrets
        let secrets_guard = (&_salt as *const u8 as usize) - MPU_MIN_SIZE;
        add_mpu_guard(mpu, 7, secrets_guard as u32);

        mpu.enable();
    }
}

static mut TICKS: AtomicU32 = AtomicU32::new(0);

/// We use the systick timer to count ms since the last time reset
#[allow(static_mut_refs)]
#[exception]
fn SysTick() {
    // All access must be atomic, so this should be safe.
    let current = unsafe { TICKS.load(Ordering::SeqCst) };
    unsafe {
        TICKS.store(current + 1, Ordering::Relaxed);
    }
}

/// Writer utility for UART0 containing the entire body of a message, the size of the body,
/// and the associated Opcode of the message.
struct UartWriter([u8; MAX_BODY_SIZE], usize, Opcode);
impl UartWriter {
    /// Initialize self to be empty, with a specified Opcode.
    fn new(opcode: Opcode) -> Self {
        Self([0; _], 0, opcode)
    }
}

impl UartWriter {
    /// Write self contained message to UART0 if a message is present and reset message length.
    fn flush(&mut self) {
        if self.1 != 0 {
            let _ = Message::write(self.2, MessagePort::UART0, &self.0[..self.1]);
            self.1 = 0;
        }
    }
}

impl Write for UartWriter {
    /// Write a string slice to UART0.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // retrieve string slice as bytes
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
