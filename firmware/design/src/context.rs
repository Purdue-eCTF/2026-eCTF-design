use mspm0l222x_hal::{
    mpu::{MemoryCacheType, MpuPerms, MpuRegionSize},
    timer::Instant,
};

use mspm0l222x_hal::{
    flash::{FLASH_PAGE_SIZE, FlashController},
    iomux::Iomux,
    mpu::Mpu,
    uart::{Uart0, Uart1},
};

#[macro_export]
/// If the board resets while running an operation, force a 5s lockout
macro_rules! sensitive {
    ($context:ident, $($body:stmt)+) => {
        $context.move_salt_to_ram();
        $($body)+
        $context.move_salt_to_flash();
    };
}

/// Prints an error to the uart port
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::context::write_fmt($crate::message::Opcode::Error, format_args!($($arg)*)));
}

/// Prints an error to the uart port
#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", format_args!($($arg)*)));
}

/// The Context contains abstracted access to the flash, including the files,
/// FAT table, and the salts (boot salt 1, ram salt, and pin salt)
pub struct Context;

impl Context {
    /// Initialize and generate a context object based on the current state of the flash.
    pub fn new(
        sysctl: mspm0l222x_hal::mspm0l222x_pac::Sysctl,
        iomux: mspm0l222x_hal::mspm0l222x_pac::Iomux,
        uart0: mspm0l222x_hal::mspm0l222x_pac::Uart0,
        uart1: mspm0l222x_hal::mspm0l222x_pac::Uart1,
        flashctl: mspm0l222x_hal::mspm0l222x_pac::Flashctl,
        mpu_regs: cortex_m::peripheral::MPU,
        systick: cortex_m::peripheral::SYST,
    ) -> Self {
        // entire ram not executable
        Mpu::sram_rw_boundary(&sysctl, 0x7fff).expect("failed to set sram rw boundary");

        let mut mpu = Mpu::new(mpu_regs);
        setup_mpu_mappings(&mut mpu);

        mspm0l222x_hal::timer::init(systick);

        let iomux = Iomux::new(&iomux);

        Uart0::init(&iomux, uart0);
        Uart1::init(&iomux, uart1);
        FlashController::init(flashctl);

        // protect all flash except for FlashEntry-s
        let flash = mspm0l222x_hal::flash::flash();
        flash.write_protect(0, 256 * FLASH_PAGE_SIZE as u32);

        Self
    }

    /// Retrieve the TICK timer's current value (in milliseconds).
    pub fn time(&self) -> Instant {
        Instant::now()
    }

    /// Retrieve the TICK timer's current value (in ticks) .
    pub fn time_ms(&self) -> u32 {
        self.time().time_since_boot().as_millis() as u32
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

        // mark only text region executable
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

        mpu.clear_region(5).unwrap();
        mpu.clear_region(6).unwrap();
        mpu.clear_region(7).unwrap();

        mpu.enable();
    }
}
