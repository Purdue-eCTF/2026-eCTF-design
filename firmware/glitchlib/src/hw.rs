//! Minimal GPIOB / IOMUX / NVIC helpers (PAC only, no HAL, no peripheral ownership, no bank resets).

use cortex_m::interrupt::InterruptNumber;
use mspm0l222x_pac::{Gpiob, Iomux};

const PWREN_WRITE_KEY: u32 = 0x2600_0000;

/// INT_GROUP1 is NVIC IRQ 1 (GPIOA, GPIOB, COMP0 and the TRNG share it).
#[derive(Clone, Copy)]
struct Group1;
unsafe impl InterruptNumber for Group1 {
    fn number(self) -> u16 {
        1
    }
}

pub const GROUP1_PRIORITY: u8 = 0x80;

fn gpiob() -> Gpiob {
    // SAFETY: register access only.
    unsafe { Gpiob::steal() }
}

/// Enable GPIOB power. Unlike the HAL's `power_on` this does NOT reset the bank, so it is safe on a bank
/// the design already configured.
pub fn gpiob_power_on() {
    gpiob()
        .gpiob_gprcm(0)
        .gpiob_pwren()
        .write(|w| unsafe { w.bits(PWREN_WRITE_KEY) }.enable().set_bit());
    for _ in core::hint::black_box(0..32) {
        cortex_m::asm::nop();
    }
}

pub enum Dir {
    Input,
    Output,
}

/// Connect IOMUX PINCM `pincm` (1-based) as GPIO (function 1).
pub fn connect_gpio(pincm: u8, dir: Dir, pull_up: bool) {
    if pincm == 0 {
        return;
    }
    // SAFETY: register access only.
    let iomux = unsafe { Iomux::steal() };
    iomux.iomux_pincm(pincm as usize - 1).write(|w| {
        unsafe { w.pf().bits(1) }
            .pc()
            .connected()
            .inena()
            .bit(matches!(dir, Dir::Input))
            .pipu()
            .bit(pull_up)
            .pipd()
            .clear_bit()
    });
}

pub fn make_output_low(pin: u8) {
    gpiob().gpiob_doutclr31_0().write(|w| unsafe { w.bits(1 << pin) });
    gpiob().gpiob_doeset31_0().write(|w| unsafe { w.bits(1 << pin) });
}

pub fn set_register() -> *mut u32 {
    gpiob().gpiob_doutset31_0().as_ptr() as *mut u32
}

pub fn clear_register() -> *mut u32 {
    gpiob().gpiob_doutclr31_0().as_ptr() as *mut u32
}

/// Falling-edge interrupt on `pin`, any stale pending flag cleared first.
pub fn enable_falling_edge_interrupt(pin: u8) {
    let g = gpiob();
    let shift = (pin as u32 % 16) * 2;
    let mask = 0b11u32 << shift;
    let value = 2u32 << shift; // 2 = falling
    if pin < 16 {
        g.gpiob_polarity15_0()
            .modify(|r, w| unsafe { w.bits((r.bits() & !mask) | value) });
    } else {
        g.gpiob_polarity31_16()
            .modify(|r, w| unsafe { w.bits((r.bits() & !mask) | value) });
    }
    let int = g.gpiob_cpu_int(0);
    int.gpiob_cpu_int_iclr().write(|w| unsafe { w.bits(1 << pin) });
    int.gpiob_cpu_int_imask()
        .modify(|r, w| unsafe { w.bits(r.bits() | (1 << pin)) });
}

pub fn pending() -> u32 {
    gpiob().gpiob_cpu_int(0).gpiob_cpu_int_mis().read().bits()
}

pub fn clear_pending(mask: u32) {
    gpiob()
        .gpiob_cpu_int(0)
        .gpiob_cpu_int_iclr()
        .write(|w| unsafe { w.bits(mask) });
}

pub fn enable_group1_interrupt() {
    // SAFETY: only touches NVIC priority/enable for IRQ 1, on a single core.
    unsafe {
        let mut nvic = cortex_m::Peripherals::steal().NVIC;
        nvic.set_priority(Group1, GROUP1_PRIORITY);
        cortex_m::peripheral::NVIC::unmask(Group1);
    }
}
