//! glitchlib: the glitch-testing features of the `design` firmware as a static library for a C design.
//!
//! Deliberately has no `cortex-m-rt`, HAL, or vector table of its own: the C design owns reset, clocks,
//! UART0 setup and the vector table. See README.md.

#![no_std]

mod debug_isr;
mod exceptions;
mod hw;
mod timing;
mod regdump;
mod trigger;
mod uart;
mod vectors;

use core::ffi::{CStr, c_char};

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[repr(C)]
pub struct DbgCfg {
    pub cpu_hz: u32,
    pub button_pincm: u8,
    pub button_pin: u8,
    pub trigger_pincm: u8,
    pub trigger_pin: u8,
    pub power_on_gpiob: u8,
    pub install_vectors: u8,
    pub reserved: [u8; 2],
}

#[unsafe(no_mangle)]
pub extern "C" fn dbg_cfg_default() -> DbgCfg {
    DbgCfg {
        cpu_hz: 32_000_000,
        button_pincm: 63,
        button_pin: 21,
        trigger_pincm: 64,
        trigger_pin: 22,
        power_on_gpiob: 0,
        install_vectors: 1,
        reserved: [0; 2],
    }
}

/// # Safety
/// `cfg` must point to a valid `dbg_cfg_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbg_init(cfg: *const DbgCfg) -> i32 {
    let cfg = unsafe { &*cfg };
    timing::set_cpu_hz(cfg.cpu_hz);
    if cfg.power_on_gpiob != 0 {
        hw::gpiob_power_on();
    }
    trigger::init(cfg.trigger_pincm, cfg.trigger_pin);
    debug_isr::init(cfg.button_pincm, cfg.button_pin);

    if cfg.install_vectors != 0 && !vectors::install() {
        return -1;
    }
    0
}

pub use debug_isr::dbg_group1_entry;
pub use exceptions::{dbg_hardfault_entry, dbg_nmi_entry};

#[unsafe(no_mangle)]
pub extern "C" fn dbg_set_chain(slot: u32, handler: Option<extern "C" fn()>) {
    vectors::set_chain(slot as usize, handler.map_or(0, |f| f as usize));
}

/// Write `len` raw bytes to UART0.
///
/// # Safety
/// `buf` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbg_write(buf: *const u8, len: usize) {
    uart::write_bytes(unsafe { core::slice::from_raw_parts(buf, len) });
}

/// Write a NUL-terminated string to UART0 (no newline added).
///
/// # Safety
/// `s` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbg_puts(s: *const c_char) {
    uart::write_bytes(unsafe { CStr::from_ptr(s) }.to_bytes());
}

/// Blocking read of one byte from UART0: the byte, or -1 on a framing/overrun error.
#[unsafe(no_mangle)]
pub extern "C" fn dbg_read_byte() -> i32 {
    uart::read_byte().map_or(-1, |b| b as i32)
}

#[unsafe(no_mangle)]
pub extern "C" fn dbg_delay_ms(ms: u32) {
    timing::delay_ms(ms)
}

/// Print `msg` + "\r\n" every 3 seconds, forever.
///
/// # Safety
/// `msg` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbg_loop_print(msg: *const c_char) -> ! {
    let msg = unsafe { CStr::from_ptr(msg) }.to_bytes();
    loop {
        uart::write_bytes(msg);
        uart::write_bytes(b"\r\n");
        timing::delay_ms(3000);
    }
}

/// Like `dbg_loop_print` but each line is prefixed with `glitch `, so the host can tell the branch reached.
///
/// # Safety
/// `msg` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbg_gprint(msg: *const c_char) -> ! {
    let msg = unsafe { CStr::from_ptr(msg) }.to_bytes();
    loop {
        uart::write_bytes(b"glitch ");
        uart::write_bytes(msg);
        uart::write_bytes(b"\r\n");
        timing::delay_ms(3000);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dbg_trigger_high() {
    trigger::drive_high()
}

#[unsafe(no_mangle)]
pub extern "C" fn dbg_trigger_low() {
    trigger::drive_low()
}

#[unsafe(no_mangle)]
pub extern "C" fn dbg_trigger_sequence() {
    trigger::sequence()
}
