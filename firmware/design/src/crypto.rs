use argon2::{self, Block};
use blake2::{Blake2s256, Digest};
use bytemuck::{Pod, Zeroable};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mspm0l222x_hal::trng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::file::File;
use crate::protocol::ProtocolError;
use crate::secrets::PUB_ENCRYPT_SALT;

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const GN_SIZE: usize = 32;

/// Metadata to append to a public-key encrypted ciphertext.
/// Includes a Diffie-Hellman public key for asymmetric enc/decryption
/// and XChaCha20-Poly1305 nonce and tag for symmetric enc/decryption.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct PubKeyMetadata {
    pub gn: [u8; GN_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
}

impl PubKeyMetadata {
    /// Clear all fields to 0.
    pub fn empty() -> Self {
        Self {
            gn: [0u8; _],
            nonce: [0u8; _],
            tag: [0u8; _],
        }
    }

    /// Encrypt a message with a public key and associated data.
    pub fn encrypt(
        msg: &mut [u8],
        public_key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<Self, ProtocolError> {
        // Reset self to be used as blocks of storage during cryptographic processes.
        let mut out = Self::empty();

        encrypt_payload_pub(
            msg,
            &mut out.gn,
            &mut out.nonce,
            &mut out.tag,
            public_key,
            associated_data,
        )?;

        Ok(out)
    }
}

/// Given a message like msg || SymmetricMetadata, decrypts and validates the message, and returns msg
pub fn unwrap_pub_message<'a>(
    msg: &'a mut [u8],
    secret_key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], ProtocolError> {
    if msg.len() < size_of::<PubKeyMetadata>() {
        return Err(CryptoError::InvalidDecryptionPayload.into());
    }

    // Differentiate between message data and it's encryption metadata and decrypt
    let (msg_inner, metadata) = msg.split_at_mut(msg.len() - size_of::<PubKeyMetadata>());
    let metadata: &PubKeyMetadata = bytemuck::from_bytes(metadata);
    decrypt_payload_pub(
        msg_inner,
        &metadata.gn,
        &metadata.nonce,
        &metadata.tag,
        secret_key,
        associated_data,
    )?;

    Ok(msg_inner)
}

/// Metadata to append to symmetrically encrypted ciphertext.
/// Includes a nonce and authentication tag for XChaCha20-Poly1305.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct SymmetricMetadata {
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
}

impl SymmetricMetadata {
    /// Clears all fields to 0.
    pub fn empty() -> Self {
        Self {
            nonce: [0u8; _],
            tag: [0u8; _],
        }
    }

    /// Encrypt data and its associated data with a symmetric key.
    pub fn encrypt(
        msg: &mut [u8],
        key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<Self, ProtocolError> {
        let mut out = Self::empty();

        encrypt_payload_symmetric(msg, &mut out.nonce, &mut out.tag, key, associated_data)?;

        Ok(out)
    }
}

/// Given a message like msg || SymmetricMetadata, decrypts and validates the message, and returns msg.
pub fn unwrap_symmetric_message<'a>(
    msg: &'a mut [u8],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], ProtocolError> {
    if msg.len() < size_of::<SymmetricMetadata>() {
        return Err(CryptoError::InvalidDecryptionPayload.into());
    }

    // Differentiate between message data and it's encryption metadata and decrypt
    let (msg_inner, metadata) = msg.split_at_mut(msg.len() - size_of::<SymmetricMetadata>());
    let metadata: &SymmetricMetadata = bytemuck::from_bytes(metadata);
    decrypt_payload_symmetric(
        msg_inner,
        &metadata.nonce,
        &metadata.tag,
        key,
        associated_data,
    )?;

    Ok(msg_inner)
}

// TODO: Tests
/// The errors that happen on a failed cryptography process, usually to do with
/// an invalid key or pin.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid decrypt payload")]
    InvalidDecryptionPayload,
    #[error("Invalid encrypt payload")]
    InvalidEncryptionPayload,
    #[error("Failed to derive key")]
    KDFFailure,
}

/// Verify a file's contents and metadata with its signature using a corresponding asymmetric encryption key
pub fn verify_signature(file: &File, key: &[u8; 32]) -> Result<(), CryptoError> {
    let pk_sign = VerifyingKey::from_bytes(key).unwrap();
    let expected_signature = Signature::from_bytes(&file.signature);
    pk_sign
        .verify(bytemuck::bytes_of(&file.protected), &expected_signature)
        .unwrap();
    Ok(())
}

/// Sign a file in place using a corresponding asymmetric encryption key.
pub fn sign_file(file: &mut File, key: &[u8; 32]) -> Result<(), CryptoError> {
    let sk_sign = SigningKey::from_bytes(key);
    let signature = sk_sign.sign(bytemuck::bytes_of(&file.protected));
    file.signature = signature.to_bytes();
    Ok(())
}

/// Decrypts an asymmetrically encrypted payload in-place.
///
/// Derives a new key from a secret key and the value G^n
/// in order to symmetrically decrypt the payload in-place.
/// 
/// See the protocol document for more detailed information.
pub fn decrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &[u8; GN_SIZE],
    nonce: &'a [u8; NONCE_SIZE],
    tag: &'a [u8; TAG_SIZE],
    secret_key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    let sk = StaticSecret::from(*secret_key);
    let pubkey = PublicKey::from(*gn);
    let shared = sk.diffie_hellman(&pubkey).to_bytes();

    // use kdf as recommended by rfc
    // TODO: maybe use real kdf, not just hash, but can't really afford performance for real kdf
    // TODO: maybe add per key salt
    let sym_key = blake_hash(&shared, &PUB_ENCRYPT_SALT);

    decrypt_payload_symmetric(payload, nonce, tag, &sym_key, associated_data)?;
    Ok(payload)
}

/// Asymmetrically encrypt data in-place.
/// The buffers gn, nonce, and tag are filled with generated metadata required for decryption.
///
/// Derives a secret key from the public key and a random n generated from the hardware TRNG.
/// The key is used to symmetrically encrypt the payload in-place.
/// 
/// See the protocol document for more detailed information.
pub fn encrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &'a mut [u8; GN_SIZE],
    nonce: &'a mut [u8; NONCE_SIZE],
    tag: &'a mut [u8; TAG_SIZE],
    public_key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    let pk = PublicKey::from(*public_key);
    let mut n_bytes = [0; 32];

    // TODO Generate random bytes from which new asymmetric keys will be made
    let trng = trng::trng();
    for chunk in n_bytes.chunks_exact_mut(4) {
        chunk.copy_from_slice(&trng.word().to_le_bytes());
    }

    let n = StaticSecret::from(n_bytes);

    let new_pk = PublicKey::from(&n);
    gn.copy_from_slice(&new_pk.to_bytes());

    // Generate shared/common secret from the diffie hellman key exchange.
    let shared = n.diffie_hellman(&pk).to_bytes();

    // use kdf as recommended by rfc
    // TODO: maybe use real kdf, not just hash, but can't really afford performance for real kdf
    // TODO: maybe add per key salt
    let secret = blake_hash(&shared, &PUB_ENCRYPT_SALT);

    encrypt_payload_symmetric(payload, nonce, tag, &secret, associated_data)?;
    Ok(payload)
}

/// Decrypt a payload in-place using XChaCha20-Poly1305.
/// 
/// See the protocol document for detailed information.
pub fn decrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    nonce: &'a [u8; NONCE_SIZE],
    tag: &'a [u8; TAG_SIZE],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidDecryptionPayload)?;

    let nonce_ga = GenericArray::from_slice(nonce);
    let tag_ga = GenericArray::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce_ga, associated_data, payload, tag_ga)
        .map_err(|_| CryptoError::InvalidDecryptionPayload)?;

    Ok(payload)
}

/// Symmetrically encrypt data in-place.
/// The nonce is written to nonce_slot and the authentication tag is written to tag_slot.
///
/// Generates a nonce with the hardware TRNG and encrypts the payload in-place using XChaCha20-Poly1305.
/// 
/// See the protocol document for detailed information.
pub fn encrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    nonce_slot: &'a mut [u8; NONCE_SIZE],
    tag_slot: &'a mut [u8; TAG_SIZE],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    let trng = trng::trng();
    for chunk in nonce_slot.chunks_exact_mut(4) {
        chunk.copy_from_slice(&trng.word().to_le_bytes());
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidEncryptionPayload)?;

    let nonce_ga = GenericArray::from_slice(nonce_slot);
    let tag = cipher
        .encrypt_in_place_detached(nonce_ga, associated_data, payload)
        .map_err(|_| CryptoError::InvalidEncryptionPayload)?;

    tag_slot.copy_from_slice(tag.as_slice());
    Ok(payload)
}

/// Implement the blake hash on data with a salt and return the resulting hash.
pub fn blake_hash(input: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut blake_hasher = Blake2s256::new();
    blake_hasher.update(input);
    blake_hasher.update(salt);
    *blake_hasher.finalize().as_array().unwrap()
}
