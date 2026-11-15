use thiserror::Error;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Cryptography failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Invalid file")]
    InvalidFile,
    #[error("Peer board returned error packet")]
    PeerBoardError,
    #[error("Storage failure")]
    StorageFailure,
    #[error("Invalid pin")]
    InvalidPin,
    #[error("Invalid message length")]
    InvalidMessageLength,
}
