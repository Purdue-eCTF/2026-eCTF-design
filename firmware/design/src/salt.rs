use crate::secrets::{
    ARGON_M_COST, ARGON_P_COST, BOOT_SALT_0, DERIVE_SALT, T_COST_BOOT, T_COST_PIN,
};
use argon2::Block;
use argon2::{Algorithm, Argon2, Params, Version};
use bytemuck::{Pod, Zeroable};

const ARGON_M_COST_USIZE: usize = ARGON_M_COST as usize;

/// Container for the salt.
#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct Salt(pub [u8; 32]);

impl Salt {
    // CORE BOOT LOGIC (Sec 5.1.1)
    // Uses the hardware TRNG and FlashController directly
    /// Generate and return boot salt 1 from boot salt 0 using timing tuned Argon2id.
    ///
    /// See the protocol document for more detailed information.
    pub fn derive_boot_salt_1() -> Self {
        let mut boot_salt_1 = [0; _];
        Salt::derive_argon(&BOOT_SALT_0, &mut boot_salt_1, T_COST_BOOT);
        Self(boot_salt_1)
    }

    /// Generate and return pin salt from boot salt 1 using timing tuned Argon2id.
    ///
    /// See the protocol document for more detailed information.
    pub fn derive_pin_salt(&self) -> Self {
        let mut salt = [0; _];
        Salt::derive_argon(&self.0, &mut salt, T_COST_PIN);
        Self(salt)
    }

    /// Use Argon2id with a specified timing cost to hash an input into the output location.
    ///
    /// See the protocol document for more detailed information.
    pub fn derive_argon(input: &[u8], output: &mut [u8], t_cost: u32) {
        // rand_ops!(trng::trng());

        // TODO: prevent this from overflowing the stack
        let mut mem = [Block::new(); ARGON_M_COST_USIZE];

        let params = Params::new(ARGON_M_COST, t_cost, ARGON_P_COST, Some(output.len()))
            .expect("Argon params invalid");

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        argon
            .hash_password_into_with_memory(input, DERIVE_SALT, output, &mut mem)
            .expect("Argon Derivation Failed");

        // rand_ops!(trng::trng());
    }
}
