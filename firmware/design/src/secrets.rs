use crate::context::Context;

use bytemuck::{Pod, Zeroable};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

#[derive(Default, Pod, Zeroable, Clone, Copy)]
#[repr(transparent)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.iter().all(|v| *v == 0)
    }
}

#[derive(Default, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct GroupKey {
    pub sk_sign: SymmetricKey,
    pub sk_read: SymmetricKey,
    pub pk_read: SymmetricKey,
    pub sk_trans: SymmetricKey, // TODO: why is this unused?
    pub sk_inter: SymmetricKey,
}

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
    fn decrypt(&self, k_auth: &[u8; 32]) -> GroupKey {
        let mut blob = self.blob.clone();
        let cipher = XChaCha20Poly1305::new(k_auth.into());
        cipher
            .decrypt_in_place_detached(&self.nonce.into(), &[], &mut blob, &self.tag.into())
            .unwrap();

        *bytemuck::from_bytes::<GroupKey>(&blob)
    }
}

pub fn get_enc_group_keys(group: u16) -> Result<&'static EncryptedGroupKey, ()> {
    for key in GROUP_KEYS_ENC.iter() {
        if key.group == group {
            return Ok(key);
        }
    }
    Err(())
}

pub fn get_group_keys_from_pin(ctx: &Context, group: u16, pin: &[u8; 6]) -> Result<GroupKey, ()> {
    let k_auth = ctx.k_auth(pin);
    let enc_keys = get_enc_group_keys(group)?;
    Ok(enc_keys.decrypt(&k_auth))
}

include!(concat!(env!("OUT_DIR"), "/secrets_generated.rs"));
