//! Raw-register UART0 access. The design owns UART setup (baud, pins, clocks); we only push/pop bytes.

use core::fmt;
use mspm0l222x_pac::Uart0;

fn regs() -> Uart0 {
    // SAFETY: register-only access; the design is assumed not to use UART0 concurrently with a debug
    // handler (the handlers run to completion and steal the UART like the original debug ISR did).
    unsafe { Uart0::steal() }
}

/// Block until all bytes are in the FIFO, without waiting for the shifter to drain.
fn push(bytes: &[u8]) {
    let u = regs();
    for &b in bytes {
        while u.uart0_stat().read().txff().bit_is_set() {}
        u.uart0_txdata().write(|w| unsafe { w.data().bits(b) });
    }
}

fn flush() {
    let u = regs();
    while u.uart0_stat().read().txfe().bit_is_clear() {}
}

pub fn write_bytes(bytes: &[u8]) {
    push(bytes);
    flush();
}

/// Blocking read of one byte. `Err` on a framing/overrun/etc. error (the byte is still popped).
pub fn read_byte() -> Result<u8, ()> {
    let u = regs();
    while u.uart0_stat().read().rxfe().bit_is_set() {}
    let r = u.uart0_rxdata().read();
    if r.brkerr().bit_is_set()
        || r.frmerr().bit_is_set()
        || r.nerr().bit_is_set()
        || r.ovrerr().bit_is_set()
        || r.parerr().bit_is_set()
    {
        return Err(());
    }
    Ok(r.data().bits())
}

struct Writer;

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        push(s.as_bytes());
        Ok(())
    }
}

pub fn write_format(args: fmt::Arguments) {
    let _ = fmt::write(&mut Writer, args);
    flush();
}

macro_rules! print {
    ($($arg:tt)*) => ($crate::uart::write_format(format_args!($($arg)*)));
}

macro_rules! println {
    () => ($crate::uart::write_format(format_args!("\n")));
    ($($arg:tt)*) => ($crate::uart::write_format(format_args!("{}\n", format_args!($($arg)*))));
}

pub(crate) use {print, println};
