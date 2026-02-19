use crate::secrets_generated::{BOOT_SALT_0, PIN};
use argon2::Block;
use argon2::{Algorithm, Argon2, Params, Version};
use bytemuck::{Pod, Zeroable};

// ARGON2 TUNING PARAMETERS
// Requirements: Boot ~4s and PIN ~1s

pub const ARGON_M_COST: u32 = 8; // memory cost in kb
const ARGON_M_COST_USIZE: usize = ARGON_M_COST as usize;
pub const ARGON_P_COST: u32 = 1; // parallelism costs

// PLACEHOLDER: Time cost (iterations) for Boot Salt 1 generation
pub const T_COST_BOOT: u32 = 1;

// Time cost for PIN Salt derivation
// TODO: tune to hit ~1 second
pub const T_COST_PIN: u32 = 1;

// Time cost for K_auth
// TODO: tune to hit ~1 second
pub const T_COST_K_AUTH: u32 = 1;

// Physical layout of the Security Page in Flash
// Size must be exactly 1024 bytes to match hardware sector erase size
// Stores Boot Salts and Lockout state

#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct Salt(pub [u8; 32]);

impl Salt {
    // CORE BOOT LOGIC (Sec 5.1.1)
    // Uses the hardware TRNG and FlashController directly
    pub fn derive_boot_salt_1() -> Self {
        let mut boot_salt_1 = [0; _];
        Salt::derive_argon(&BOOT_SALT_0, &mut boot_salt_1, T_COST_BOOT);
        Self(boot_salt_1)
    }

    pub fn derive_pin_salt(&self) -> Self {
        let mut salt = [0; _];
        Salt::derive_argon(&self.0, &mut salt, T_COST_PIN);
        Self(salt)
    }

    pub fn derive_argon(input: &[u8], output: &mut [u8], t_cost: u32) {
        // TODO: prevent this from overflowing the stack
        let mut mem = [Block::new(); ARGON_M_COST_USIZE];
        const DERIVE_SALT: &[u8] = b"ectf-deriv";

        let params = Params::new(ARGON_M_COST, t_cost, ARGON_P_COST, Some(output.len()))
            .expect("Argon Params Invalid");

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        argon
            .hash_password_into_with_memory(input, DERIVE_SALT, output, &mut mem)
            .expect("Argon Derivation Failed");
    }
}
