#![no_std]
#![feature(int_from_ascii)]

use core::fmt;

use bytemuck::{Pod, Zeroable};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::rand_core::{CryptoRng, RngCore};
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305};
use serde::de::Visitor;
use serde::{Deserialize, de};

#[derive(Default, Pod, Zeroable, Clone, Copy, Debug)]
#[repr(transparent)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|v| *v == 0)
    }
}

#[derive(Default, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct GroupKey {
    pub sk_sign: SymmetricKey,
    pub sk_read: SymmetricKey,
    pub pk_read: SymmetricKey,
    pub sk_trans: SymmetricKey,
    pub sk_inter: SymmetricKey,
}

#[derive(Debug)]
pub struct EncryptedGroupKey {
    pub group: u16,
    pub blob: [u8; core::mem::size_of::<GroupKey>()],
    pub tag: [u8; 16],
    pub nonce: [u8; 24],
    pub pk_sign: SymmetricKey,
    pub pk_trans: SymmetricKey,
    pub pk_inter: SymmetricKey,
}

impl EncryptedGroupKey {
    pub fn decrypt(&self, k_auth: &[u8; 32]) -> GroupKey {
        let mut blob = self.blob.clone();
        let cipher = XChaCha20Poly1305::new(k_auth.into());
        cipher
            .decrypt_in_place_detached(&self.nonce.into(), &[], &mut blob, &self.tag.into())
            .unwrap();

        *bytemuck::from_bytes::<GroupKey>(&blob)
    }
}

impl EncryptedGroupKey {
    pub fn from_group_keys(
        rng: &mut (impl CryptoRng + RngCore),
        group: u16,
        group_keys: &GroupKey,
        k_auth: &SymmetricKey,
        pk_sign: SymmetricKey,
        pk_trans: SymmetricKey,
        pk_inter: SymmetricKey,
    ) -> Self {
        let mut blob: [u8; core::mem::size_of::<GroupKey>()] = [0; _];
        blob.copy_from_slice(bytemuck::bytes_of(group_keys));

        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&k_auth.0));
        let nonce = XChaCha20Poly1305::generate_nonce(rng);

        let group_bytes = group.to_le_bytes();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &group_bytes, &mut blob)
            .expect("failed to encrypt group keys");

        EncryptedGroupKey {
            group,
            blob,
            tag: *tag.as_array().unwrap(),
            nonce: *nonce.as_array().unwrap(),
            pk_sign,
            pk_trans,
            pk_inter,
        }
    }
}

// traitslop

struct SymmetricKeyParser;
impl SymmetricKeyParser {
    fn fromhex(s: &str) -> Option<SymmetricKey> {
        if s.len() != 64 {
            return None;
        }

        let mut value = [0; 32];

        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let Ok(hex) = u8::from_ascii_radix(pair, 16) else {
                return None;
            };
            value[i] = hex;
        }

        Some(SymmetricKey(value))
    }
}

impl<'de> Visitor<'de> for SymmetricKeyParser {
    type Value = SymmetricKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("64-character (32-byte) hex string")
    }

    fn visit_str<E>(self, value: &str) -> Result<SymmetricKey, E>
    where
        E: de::Error,
    {
        SymmetricKeyParser::fromhex(value).ok_or(de::Error::invalid_value(
            de::Unexpected::Str(value),
            &"A hex string",
        ))
    }
}

impl<'de> Deserialize<'de> for SymmetricKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(SymmetricKeyParser)
    }
}
