use argon2::{self, Block};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use mspm0l222x_hal::trng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const GN_SIZE: usize = 32;

pub const METADATA_SIZE_PUB: usize = NONCE_SIZE + TAG_SIZE + GN_SIZE;

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

// expect gn || ct
pub fn decrypt_payload_pub_combined<'a>(payload: &'a mut [u8], key: &[u8; 32]) -> Result<&'a mut [u8], CryptoError> {
    if (payload.len() < GN_SIZE) {
        return Err(CryptoError::InvalidDecryptionPayload);
    }
    let (gn, body) = payload.split_at_mut(GN_SIZE);
    let (nonce, rest) = body.split_at_mut(NONCE_SIZE);
    let (ct, tag) = rest.split_at_mut(rest.len() - TAG_SIZE);
    let gn: &[u8; GN_SIZE] = bytemuck::from_bytes(gn);
    let nonce: &[u8; NONCE_SIZE] = bytemuck::from_bytes(nonce);
    let tag: &[u8; TAG_SIZE] = bytemuck::from_bytes(tag);
    decrypt_payload_pub(ct, nonce, tag, key, gn)?;
    Ok(ct)
}

pub fn decrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    nonce: &'a [u8; NONCE_SIZE],
    tag: &'a [u8; TAG_SIZE],
    key: &[u8; 32],
    gn: &[u8; GN_SIZE],
) -> Result<&'a mut [u8], CryptoError> {
    let sk = StaticSecret::from(key.clone());
    let pubkey = PublicKey::from(gn.clone());
    let shared = sk.diffie_hellman(&pubkey).to_bytes();

    let mut sym_key = [0u8; 32];
    let memory = Block::new();

    argon2::Argon2::default()
        .hash_password_into_with_memory(&shared, gn, &mut sym_key, [memory])
        .map_err(|_| CryptoError::KDFFailure)?;

    decrypt_payload_symmetric(payload, nonce, tag, &sym_key, &[])?;
    Ok(payload)
}

//TODO, make gn slot requirement more explicit
pub fn encrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &'a mut [u8; GN_SIZE],
    nonce: &'a mut [u8; 24],
    tag: &'a mut [u8; 16],
    key: &[u8; 32],
) -> Result<&'a mut [u8], CryptoError> {
    if key.len() < GN_SIZE {
        return Err(CryptoError::InvalidEncryptionPayload);
    }

    for chunk in gn.chunks_exact_mut(4) {
        chunk.copy_from_slice(&trng::trng().word().to_le_bytes());
    }
    let sk = StaticSecret::from(key.clone());
    let pubkey = PublicKey::from(gn.clone());
    let shared = sk.diffie_hellman(&pubkey).to_bytes();

    encrypt_payload_symmetric(payload, nonce, tag, &shared, &[])?;
    Ok(payload)
}

pub fn decrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    nonce: &'a [u8; 24],
    tag: &'a [u8; 16],
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
