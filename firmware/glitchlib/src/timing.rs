//! Core clock value (from the config) and busy-wait delays based on it.

use core::sync::atomic::{AtomicU32, Ordering};

static CPU_HZ: AtomicU32 = AtomicU32::new(0);

pub fn set_cpu_hz(hz: u32) {
    CPU_HZ.store(hz, Ordering::Relaxed);
}

pub fn cpu_hz() -> u32 {
    match CPU_HZ.load(Ordering::Relaxed) {
        0 => 32_000_000,
        hz => hz,
    }
}

pub fn delay_ms(ms: u32) {
    // per-ms so the cycle count can't overflow u32 for long delays
    for _ in 0..ms {
        cortex_m::asm::delay(cpu_hz() / 1000);
    }
}
