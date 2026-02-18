use argon2::{self, Block};
use bytemuck::{Pod, Zeroable};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mspm0l222x_hal::trng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::file::File;

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const GN_SIZE: usize = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct PubKeyMetadata {
    pub gn: [u8; GN_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct SymmetricMetadata {
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
}

impl SymmetricMetadata {
    pub fn empty() -> Self {
        Self {
            nonce: [0u8; _],
            tag: [0u8; _],
        }
    }
}

// TODO: Tests
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid decrypt payload")]
    InvalidDecryptionPayload,
    #[error("Invalid encrypt payload")]
    InvalidEncryptionPayload,
    #[error("Failed to derive key")]
    KDFFailure,
}

// TODO: Have these keys use a reference to the type instead of a byte array
// so we don't accidently pass in a pubkey to a function that expects a sym_key
// and vice versa
pub fn verify_signature(file: &File, key: &[u8; 32]) -> Result<(), CryptoError> {
    let pk_sign = VerifyingKey::from_bytes(key).unwrap();
    let expected_signature = Signature::from_bytes(&file.signature);
    pk_sign
        .verify(bytemuck::bytes_of(&file.protected), &expected_signature)
        .unwrap();
    Ok(())
}

pub fn sign_file(file: &mut File, key: &[u8; 32]) -> Result<(), CryptoError> {
    let sk_sign = SigningKey::from_bytes(key);
    let signature = sk_sign.sign(bytemuck::bytes_of(&file.protected));
    file.signature = signature.to_bytes();
    Ok(())
}

pub fn decrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &[u8; GN_SIZE],
    nonce: &'a [u8; NONCE_SIZE],
    tag: &'a [u8; TAG_SIZE],
    secret_key: &[u8; 32],
) -> Result<&'a mut [u8], CryptoError> {
    let sk = StaticSecret::from(*secret_key);
    let pubkey = PublicKey::from(*gn);
    let shared = sk.diffie_hellman(&pubkey).to_bytes();

    let mut sym_key = [0u8; 32];
    let memory = Block::new();

    // TODO: params
    argon2::Argon2::default()
        .hash_password_into_with_memory(&shared, &[], &mut sym_key, [memory])
        .map_err(|_| CryptoError::KDFFailure)?;

    decrypt_payload_symmetric(payload, nonce, tag, &sym_key, &[])?;
    Ok(payload)
}

//TODO, make gn slot requirement more explicit
pub fn encrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &'a mut [u8; GN_SIZE],
    nonce: &'a mut [u8; NONCE_SIZE],
    tag: &'a mut [u8; TAG_SIZE],
    public_key: &[u8; 32],
) -> Result<&'a mut [u8], CryptoError> {
    let pk = PublicKey::from(*public_key);
    let mut n_bytes = [0; 32];

    let trng = trng::trng();
    for chunk in n_bytes.chunks_exact_mut(4) {
        chunk.copy_from_slice(&trng.word().to_le_bytes());
    }

    let n = StaticSecret::from(n_bytes);

    let new_pk = PublicKey::from(&n);
    gn.copy_from_slice(&new_pk.to_bytes());

    let shared = n.diffie_hellman(&pk).to_bytes();

    let memory = Block::new();
    let mut secret = [0; 32];

    // TODO: params
    argon2::Argon2::default()
        .hash_password_into_with_memory(&shared, &[], &mut secret, [memory])
        .map_err(|_| CryptoError::KDFFailure)?;

    encrypt_payload_symmetric(payload, nonce, tag, &secret, &[])?;
    Ok(payload)
}

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
