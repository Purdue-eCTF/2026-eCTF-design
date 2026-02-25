use argon2::{self, Block};
use blake2::digest::{FixedOutputReset, Output, OutputSizeUser, Reset};
use blake2::{Blake2b512, Blake2s256, Digest as BlakeDigest};
use bytemuck::{Pod, Zeroable};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use design_macros::rand_ops;
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign_prehashed, raw_verify_prehashed};
use ed25519_dalek::{Digest as DalekDigest, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mspm0l222x_hal::trng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::file::File;
use crate::protocol::ProtocolError;
use crate::secrets::PUB_ENCRYPT_SALT;

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

impl PubKeyMetadata {
    pub const fn empty() -> Self {
        Self {
            gn: [0u8; _],
            nonce: [0u8; _],
            tag: [0u8; _],
        }
    }

    pub fn encrypt(
        msg: &mut [u8],
        public_key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<Self, ProtocolError> {
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

    pub fn decrypt(
        &self,
        ct: &mut [u8],
        secret_key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<(), ProtocolError> {
        decrypt_payload_pub(
            ct,
            &self.gn,
            &self.nonce,
            &self.tag,
            secret_key,
            associated_data,
        )?;

        Ok(())
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

    let (msg_inner, metadata) = msg.split_at_mut(msg.len() - size_of::<PubKeyMetadata>());
    let metadata: &PubKeyMetadata = bytemuck::from_bytes(metadata);
    metadata.decrypt(msg_inner, secret_key, associated_data)?;

    Ok(msg_inner)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct SymmetricMetadata {
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
}

impl SymmetricMetadata {
    pub const fn empty() -> Self {
        Self {
            nonce: [0u8; _],
            tag: [0u8; _],
        }
    }

    pub fn encrypt(
        msg: &mut [u8],
        key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<Self, ProtocolError> {
        let mut out = Self::empty();

        encrypt_payload_symmetric(msg, &mut out.nonce, &mut out.tag, key, associated_data)?;

        Ok(out)
    }

    pub fn decrypt(
        &self,
        ct: &mut [u8],
        key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<(), ProtocolError> {
        decrypt_payload_symmetric(ct, &self.nonce, &self.tag, key, associated_data)?;

        Ok(())
    }
}

/// Given a message like msg || SymmetricMetadata, decrypts and validates the message, and returns msg
pub fn unwrap_symmetric_message<'a>(
    msg: &'a mut [u8],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], ProtocolError> {
    if msg.len() < size_of::<SymmetricMetadata>() {
        return Err(CryptoError::InvalidDecryptionPayload.into());
    }

    let (msg_inner, metadata) = msg.split_at_mut(msg.len() - size_of::<SymmetricMetadata>());
    let metadata: &SymmetricMetadata = bytemuck::from_bytes(metadata);
    metadata.decrypt(msg_inner, key, associated_data)?;

    Ok(msg_inner)
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
    #[error("Invalid signature")]
    InvalidSignature,
}

// TODO: Have these keys use a reference to the type instead of a byte array
// so we don't accidently pass in a pubkey to a function that expects a sym_key
// and vice versa
pub fn verify_signature(file: &File, key: &[u8; 32]) -> Result<(), CryptoError> {
    // rand_ops!(trng::trng());

    let mut hasher = Blake2b512::new();
    hasher.update(bytemuck::bytes_of(&file.protected));

    // key bytes should never be invalid
    let pk_sign = VerifyingKey::from_bytes(key).unwrap();
    let expected_signature = Signature::from_bytes(&file.signature);
    raw_verify_prehashed::<Blake2b512, Blake2b512>(&pk_sign, hasher, None, &expected_signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    // rand_ops!(trng::trng());

    Ok(())
}

pub fn sign_file(file: &mut File, key: &[u8; 32]) -> Result<(), CryptoError> {
    // rand_ops!(trng::trng());

    // expand secret key with blake2b
    // this is pretty much copied what ed25519_dalek does, just with blake2b instead
    let mut hasher = Blake2b512::new();
    hasher.update(key);
    let expanded_array = hasher.finalize();
    // unwrap should never fail
    let expanded_bytes = expanded_array.as_array().unwrap();

    let expanded_key = ExpandedSecretKey::from_bytes(expanded_bytes);
    let public_key = VerifyingKey::from(&expanded_key);

    let mut file_hasher = Blake2b512::new();
    file_hasher.update(bytemuck::bytes_of(&file.protected));

    // shouldn't fail, context is None
    file.signature =
        raw_sign_prehashed::<Blake2b512, Blake2b512>(&expanded_key, file_hasher, &public_key, None)
            .unwrap()
            .to_bytes();

    // rand_ops!(trng::trng());

    Ok(())
}

pub fn decrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &[u8; GN_SIZE],
    nonce: &'a [u8; NONCE_SIZE],
    tag: &'a [u8; TAG_SIZE],
    secret_key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    // rand_ops!(trng::trng());

    let sk = StaticSecret::from(*secret_key);
    let pubkey = PublicKey::from(*gn);
    let shared = sk.diffie_hellman(&pubkey).to_bytes();

    // rand_ops!(trng::trng());

    // use kdf as recommended by rfc
    // TODO: maybe use real kdf, not just hash, but can't really afford performance for real kdf
    // TODO: maybe add per key salt
    let sym_key = blake_hash(&shared, &PUB_ENCRYPT_SALT);

    // decrypt payload already have rand ops
    decrypt_payload_symmetric(payload, nonce, tag, &sym_key, associated_data)?;
    Ok(payload)
}

//TODO, make gn slot requirement more explicit
pub fn encrypt_payload_pub<'a>(
    payload: &'a mut [u8],
    gn: &'a mut [u8; GN_SIZE],
    nonce: &'a mut [u8; NONCE_SIZE],
    tag: &'a mut [u8; TAG_SIZE],
    public_key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    // rand_ops!(trng::trng());

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

    // rand_ops!(trng::trng());

    // use kdf as recommended by rfc
    // TODO: maybe use real kdf, not just hash, but can't really afford performance for real kdf
    // TODO: maybe add per key salt
    let secret = blake_hash(&shared, &PUB_ENCRYPT_SALT);

    encrypt_payload_symmetric(payload, nonce, tag, &secret, associated_data)?;
    Ok(payload)
}

pub fn decrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    nonce: &'a [u8; NONCE_SIZE],
    tag: &'a [u8; TAG_SIZE],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    // rand_ops!(trng::trng());

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidDecryptionPayload)?;

    let nonce_ga = GenericArray::from_slice(nonce);
    let tag_ga = GenericArray::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce_ga, associated_data, payload, tag_ga)
        .map_err(|_| CryptoError::InvalidDecryptionPayload)?;

    // rand_ops!(trng::trng());

    Ok(payload)
}

pub fn encrypt_payload_symmetric<'a>(
    payload: &'a mut [u8],
    nonce_slot: &'a mut [u8; NONCE_SIZE],
    tag_slot: &'a mut [u8; TAG_SIZE],
    key: &[u8; 32],
    associated_data: &[u8],
) -> Result<&'a mut [u8], CryptoError> {
    // rand_ops!(trng::trng());

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

    // rand_ops!(trng::trng());

    Ok(payload)
}

pub fn blake_hash(input: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    // rand_ops!(trng::trng());

    let mut blake_hasher = Blake2s256::new();
    blake_hasher.update(input);
    blake_hasher.update(salt);
    let result = *blake_hasher.finalize().as_array().unwrap();

    // rand_ops!(trng::trng());

    result
}
