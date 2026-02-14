use argon2::{self, Block};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use mspm0l222x_hal::trng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const GN_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid decrypt payload")]
    InvalidDecryptionPayload,
    #[error("Invalid encrypt payload")]
    InvalidEncryptionPayload,
    #[error("Failed to derive key")]
    KDFFailure,
}

pub fn decrypt_payload_pub<'a>(
    payload: &'a mut [u8],
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

    decrypt_payload_symmetric(payload, &sym_key, &[])?;
    Ok(payload)
}

pub fn encrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    key: &[u8; 32],
) -> Result<&'a mut [u8], CryptoError> {
    todo!()
}

pub fn decrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidDecryptionPayload)?;

    let (nonce, rest) = payload.split_at_mut(NONCE_SIZE);
    if rest.len() < TAG_SIZE {
        return Err(CryptoError::InvalidDecryptionPayload);
    }
    let (ctxt, tag_bytes) = rest.split_at_mut(rest.len() - TAG_SIZE);

    let nonce_ga = GenericArray::from_slice(nonce);
    let tag_ga = GenericArray::from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(nonce_ga, associated_data, ctxt, tag_ga)
        .map_err(|_| CryptoError::InvalidDecryptionPayload)?;

    Ok(ctxt)
}

pub fn encrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    let (nonce_slot, rest) = payload.split_at_mut(NONCE_SIZE);
    if rest.len() < TAG_SIZE {
        return Err(CryptoError::InvalidEncryptionPayload);
    }
    let (ptxt, tag_slot) = rest.split_at_mut(rest.len() - TAG_SIZE);

    for chunk in nonce_slot.chunks_exact_mut(4) {
        chunk.copy_from_slice(&trng::trng().word().to_le_bytes());
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidEncryptionPayload)?;

    let nonce_ga = GenericArray::from_slice(nonce_slot);
    let tag = cipher
        .encrypt_in_place_detached(nonce_ga, associated_data, ptxt)
        .map_err(|_| CryptoError::InvalidEncryptionPayload)?;

    tag_slot.copy_from_slice(tag.as_slice());
    Ok(payload)
}
