use crate::file::{File, FileName};
use crate::message::{MessageError, Opcode};
use bytemuck::{Pod, Zeroable, bytes_of, bytes_of_mut};
use common::{AsymmetricKey, SymmetricKey};
use thiserror::Error;

use crate::crypto::{CryptoError, PubKeyMetadata, SymmetricMetadata};

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

    fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), ProtocolError> {
        let details = self.details();
        *details.metadata = SymmetricMetadata::encrypt(details.body, key, details.associated_data)?;
        Ok(())
    }

    fn encrypt_with_associated_data(
        &mut self,
        key: &SymmetricKey,
        associated_data: &[u8],
    ) -> Result<(), ProtocolError> {
        let details = self.details();
        *details.metadata = SymmetricMetadata::encrypt(details.body, key, associated_data)?;
        Ok(())
    }

    fn decrypt(&mut self, key: &SymmetricKey) -> Result<(), ProtocolError> {
        let details = self.details();
        details
            .metadata
            .decrypt(details.body, key, details.associated_data)?;
        Ok(())
    }

    fn decrypt_with_associated_data(
        &mut self,
        key: &SymmetricKey,
        associated_data: &[u8],
    ) -> Result<(), ProtocolError> {
        let details = self.details();
        details
            .metadata
            .decrypt(details.body, key, associated_data)?;
        Ok(())
    }
}

pub trait PubEncryptable {
    fn details(&mut self) -> EncryptionDetails<'_, PubKeyMetadata>;

    fn encrypt(&mut self, key: &AsymmetricKey) -> Result<(), ProtocolError> {
        let details = self.details();
        *details.metadata = PubKeyMetadata::encrypt(details.body, &key, details.associated_data)?;
        Ok(())
    }

    fn decrypt(&mut self, key: &AsymmetricKey) -> Result<(), ProtocolError> {
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

///////////////////////////////////////////////////////////////////////////////
////////// Transfer                                                  //////////
///////////////////////////////////////////////////////////////////////////////

const TRANSFER_ASSOCIATED_DATA: &'static [u8] = &[Opcode::Receive as u8];

/////////////
// Request //
/////////////

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct TransferRequest {
    pub slot: u8,
}

impl TransferRequest {
    pub fn new(slot: u8) -> Self {
        Self { slot }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct EncryptedTransferRequest {
    pub protected: TransferRequest,
    pub metadata: SymmetricMetadata,
}

impl SymEncryptable for EncryptedTransferRequest {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata> {
        let Self {
            protected,
            metadata,
        } = self;

        EncryptionDetails {
            body: bytes_of_mut(protected),
            associated_data: TRANSFER_ASSOCIATED_DATA,
            metadata,
        }
    }
}

//////////////
// Response //
//////////////

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct TransferResponseHeader {
    pub pub_metadata: PubKeyMetadata,
    pub group_id: GroupId,
}

// #[repr(C)]
// #[derive(Clone, Copy, Pod, Zeroable)]
// pub struct TransferResponse {
//     // header is sent first
//     pub header: TransferResponseHeader,
//     // file is received async, so shared secret can be computed, and verifying key can also be pre computed
//     pub file: File,
// }

// impl PubEncryptable for TransferResponse {
//     fn details(&mut self) -> EncryptionDetails<'_, PubKeyMetadata> {
//         let Self {
//             header:
//                 TransferResponseHeader {
//                     pub_metadata,
//                     group_id,
//                 },
//             file,
//         } = self;

//         EncryptionDetails {
//             body: bytes_of_mut(file),
//             associated_data: bytes_of(group_id),
//             metadata: pub_metadata,
//         }
//     }
// }

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct EncryptedTransferResponseHeader {
    pub protected: TransferResponseHeader,
    pub metadata: SymmetricMetadata,
}

impl SymEncryptable for EncryptedTransferResponseHeader {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata> {
        let Self {
            protected,
            metadata,
        } = self;

        EncryptionDetails {
            body: bytes_of_mut(protected),
            associated_data: TRANSFER_ASSOCIATED_DATA,
            metadata,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct EncryptedTransferResponseBody {
    pub protected: File,
    pub metadata: SymmetricMetadata,
}

impl SymEncryptable for EncryptedTransferResponseBody {
    fn details(&mut self) -> EncryptionDetails<'_, SymmetricMetadata> {
        let Self {
            protected,
            metadata,
        } = self;

        EncryptionDetails {
            body: bytes_of_mut(protected),
            associated_data: TRANSFER_ASSOCIATED_DATA,
            metadata,
        }
    }
}
