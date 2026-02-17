use crate::message::Opcode;
use crate::secrets::TRANSFER_KEYS;
use bytemuck::{Pod, Zeroable};

use crate::crypto::{SymmetricMetadata, CryptoError, encrypt_payload_symmetric};

//TODO: Have other methods use
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct TransferM0Encrypted {
    pub ct: [u8; 3],
    pub sm: SymmetricMetadata,
}

impl TransferM0Encrypted {
    pub fn empty() -> Self {
        Self {
            ct: [0u8; _],
            sm: SymmetricMetadata::empty(),
        }
    }
}

pub struct TransferM0 {
    pub slot: u8,
    pub group: u16,
}

// Create M_0 as described in [5.3.4] and write to response
// Errors if response is too large
// TODO: Should error if T0 doesn't exist

impl TransferM0 {
    pub fn encrypt(&self) -> Result<TransferM0Encrypted, CryptoError> {
        let mut r = TransferM0Encrypted::empty();
        r.ct[0] = self.slot;
        r.ct[1..3].clone_from_slice(&self.group.to_le_bytes());

        let t0 = TRANSFER_KEYS[0].0;
        encrypt_payload_symmetric(&mut r.ct, &mut r.sm.nonce, &mut r.sm.tag, &t0, &[Opcode::Receive.into()])?;
        Ok(r)
    }

    pub fn new(slot: u8, group: u16) -> Self {
        Self { slot, group }
    }
}
