use crate::file::{File, FileName};
use crate::message::{Message, MessageError, MessagePort, Opcode};
use crate::secrets::TRANSFER_SEND;
use bytemuck::{Pod, Zeroable, bytes_of, bytes_of_mut};
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

pub const INTERROGATE_MAX_GROUPS: usize = 32;
pub const MAX_NUM_FILES: usize = 8;

/// Group id which does not require alignment
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
pub struct GroupId([u8; 2]);

impl GroupId {
    pub fn get(self) -> u16 {
        u16::from_le_bytes(self.0)
    }

    pub fn set(&mut self, id: u16) {
        self.0 = id.to_le_bytes();
    }

    pub fn new(id: u16) -> Self {
        Self(id.to_le_bytes())
    }
}

pub struct EncryptionDetails<'a, T> {
    body: &'a mut [u8],
    associated_data: &'a [u8],
    metadata: &'a mut T,
}

pub trait SymEncryptable {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata>;

    fn encrypt(&mut self, key: &[u8; 32]) -> Result<(), ProtocolError> {
        let details = self.details();
        *details.metadata = SymmetricMetadata::encrypt(details.body, key, details.associated_data)?;
        Ok(())
    }

    fn decrypt(&mut self, key: &[u8; 32]) -> Result<(), ProtocolError> {
        let details = self.details();
        details
            .metadata
            .decrypt(details.body, key, details.associated_data)?;
        Ok(())
    }
}

pub trait PubEncryptable {
    fn details(&mut self) -> EncryptionDetails<'_, PubKeyMetadata>;

    fn encrypt(&mut self, key: &[u8; 32]) -> Result<(), ProtocolError> {
        let details = self.details();
        *details.metadata = PubKeyMetadata::encrypt(details.body, key, details.associated_data)?;
        Ok(())
    }

    fn decrypt(&mut self, key: &[u8; 32]) -> Result<(), ProtocolError> {
        let details = self.details();
        details
            .metadata
            .decrypt(details.body, key, details.associated_data)?;
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
////////// Interrogate                                               //////////
///////////////////////////////////////////////////////////////////////////////

const INTARROGATE_ASSOCIATED_DATA: &'static [u8] = &[Opcode::Interrogate as u8];

/////////////
// Request //
/////////////

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct InterrogateRequest {
    pub group_count: u8,
    pub groups: [GroupId; INTERROGATE_MAX_GROUPS],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct EncryptedInterrogateRequest {
    pub protected: InterrogateRequest,
    pub metadata: SymmetricMetadata,
}

impl SymEncryptable for EncryptedInterrogateRequest {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata> {
        let Self {
            protected,
            metadata,
        } = self;

        EncryptionDetails {
            body: bytes_of_mut(protected),
            associated_data: INTARROGATE_ASSOCIATED_DATA,
            metadata,
        }
    }
}

//////////////
// Response //
//////////////

#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct InterrogateFileProtected {
    pub slot: u8,
    pub name: FileName,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct InterrogateFileInfo {
    pub protected: InterrogateFileProtected,
    pub group_id: GroupId,
    pub metadata: SymmetricMetadata,
}

impl SymEncryptable for InterrogateFileInfo {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata> {
        let Self {
            protected,
            group_id,
            metadata,
        } = self;

        EncryptionDetails {
            body: bytes_of_mut(protected),
            associated_data: bytes_of(group_id),
            metadata,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct InterrogateResponse {
    pub file_count: u8,
    pub files: [InterrogateFileInfo; MAX_NUM_FILES],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct EncryptedInterrogateResponse {
    pub protected: InterrogateResponse,
    pub metadata: SymmetricMetadata,
}

impl SymEncryptable for EncryptedInterrogateResponse {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata> {
        let Self {
            protected,
            metadata,
        } = self;

        EncryptionDetails {
            body: bytes_of_mut(protected),
            associated_data: INTARROGATE_ASSOCIATED_DATA,
            metadata,
        }
    }
}
