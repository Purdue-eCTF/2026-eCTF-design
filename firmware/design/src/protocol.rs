use crate::file::File;
use crate::message::{Message, MessageError, MessagePort, Opcode};
use crate::secrets::TRANSFER_SEND;
use bytemuck::{Pod, Zeroable, bytes_of};
use thiserror::Error;

use crate::crypto::{
    CryptoError, PubKeyMetadata, SymmetricMetadata, decrypt_payload_symmetric,
    encrypt_payload_symmetric,
};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Cryptography failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Message failure: {0}")]
    Message(#[from] MessageError),
    #[error("Invalid pin")]
    InvalidPin,
    #[error("Invalid group")]
    InvalidGroup,
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Invalid slot")]
    InvalidSlot,
    #[error("Invalid file")]
    InvalidFile,
    #[error("Invalid opcode")]
    InvalidOpcode,
    #[error("Peer board returned error packet")]
    PeerBoardError,
    #[error("Storage failure")]
    StorageFailure,
}

//TODO: Have other methods use
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct TransferM0Encrypted {
    pub ct: [u8; 1],
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
        let t0 = TRANSFER_SEND.0;
        let mut pt = self.ct;

        decrypt_payload_symmetric(
            &mut pt,
            &self.sm.nonce,
            &self.sm.tag,
            &t0,
            &[Opcode::Receive.into()],
        )?;

        let mut r = TransferM0::empty();
        r.slot = pt[0];
        Ok(r)
    }
}

pub struct TransferM0 {
    pub slot: u8,
}

// Create M_0 as described in [5.3.4] and write to response
// Errors if response is too large
// TODO: Should error if T0 doesn't exist

impl TransferM0 {
    pub fn empty() -> Self {
        Self { slot: 0 }
    }
    pub fn encrypt(&self) -> Result<TransferM0Encrypted, CryptoError> {
        let mut r = TransferM0Encrypted::empty();
        r.ct[0] = self.slot;

        let t0 = TRANSFER_SEND.0;
        encrypt_payload_symmetric(
            &mut r.ct,
            &mut r.sm.nonce,
            &mut r.sm.tag,
            &t0,
            &[Opcode::Receive.into()],
        )?;
        Ok(r)
    }

    pub fn new(slot: u8) -> Self {
        Self { slot }
    }
}

// Initiates a transfer over UART1 using the protocol described in [5.3.4]
// Requested slot and group is encrypted with T0 and sent to adjacent HSM

pub fn initiate_transfer(slot: u8) -> Result<(), ProtocolError> {
    let t0 = TransferM0::new(slot);
    let t0_enc = t0.encrypt().map_err(ProtocolError::Crypto)?;
    let body = bytes_of(&t0_enc);

    Message::write(Opcode::Receive, MessagePort::UART1, body)?;

    Ok(())
}

pub const TRANSFER_RECEIVE_MAX_LENGTH: usize = size_of::<File>()
    + size_of::<PubKeyMetadata>()
    + size_of::<u16>()
    + size_of::<SymmetricMetadata>();
