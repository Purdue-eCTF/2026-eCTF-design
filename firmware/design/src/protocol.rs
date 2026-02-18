use crate::file::File;
use crate::message::{self, Message, MessageError, MessagePort, Opcode};
use crate::secrets::TRANSFER_KEYS;
use bytemuck::{Pod, Zeroable, bytes_of};
use thiserror::Error;

use crate::crypto::{
    CryptoError, PubKeyMetadata, SymmetricMetadata, decrypt_payload_symmetric,
    encrypt_payload_symmetric,
};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Cryptography failure")]
    Crypto(CryptoError),
    #[error("Message failure")]
    Message(MessageError),
}

//TODO: Have other methods use
#[repr(C, packed)]
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

    pub fn decrypt(&self) -> Result<TransferM0, CryptoError> {
        let t0 = TRANSFER_KEYS[0].0;
        let mut pt = [0u8, 3];
        pt.clone_from_slice(&self.ct);
        decrypt_payload_symmetric(
            &mut pt,
            &self.sm.nonce,
            &self.sm.tag,
            &t0,
            &[Opcode::Receive.try_into().unwrap()],
        )?;

        let mut r = TransferM0::empty();
        r.slot = pt[0];
        r.group = u16::from_le_bytes(pt[1..3].try_into().unwrap());
        Ok(r)
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
    pub fn empty() -> Self {
        Self { slot: 0, group: 0 }
    }
    pub fn encrypt(&self) -> Result<TransferM0Encrypted, CryptoError> {
        let mut r = TransferM0Encrypted::empty();
        r.ct[0] = self.slot;
        r.ct[1..3].clone_from_slice(&self.group.to_le_bytes());

        let t0 = TRANSFER_KEYS[0].0;
        encrypt_payload_symmetric(
            &mut r.ct,
            &mut r.sm.nonce,
            &mut r.sm.tag,
            &t0,
            &[Opcode::Receive.into()],
        )?;
        Ok(r)
    }

    pub fn new(slot: u8, group: u16) -> Self {
        Self { slot, group }
    }
}

// Initiates a transfer over UART1 using the protocol described in [5.3.4]
// Requested slot and group is encrypted with T0 and sent to adjacent HSM

pub fn initiate_transfer(slot: u8, group: u16) -> Result<(), ProtocolError> {
    let t0 = TransferM0::new(slot, group);
    let t0_enc = t0.encrypt().map_err(|e| ProtocolError::Crypto(e))?;
    let body = bytes_of(&t0_enc);
    let body_len: u16 = body.len().try_into().unwrap();

    Message::write_header(Opcode::Receive, body_len, MessagePort::UART1);
    Message::write_block(body, MessagePort::UART1).map_err(|e| ProtocolError::Message(e))?;

    Ok(())
}

pub const TRANSFER_RECEIVE_MAX_LENGTH: usize =
    size_of::<File>() + size_of::<PubKeyMetadata>() + size_of::<SymmetricMetadata>();

