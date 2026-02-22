use crate::{context::Context, protocol::ProtocolError};
use common::{EncryptedGroupKey, GroupKey, SymmetricKey};

use bytemuck::{Pod, Zeroable};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

pub fn get_enc_group_keys(group: u16) -> Result<&'static EncryptedGroupKey, ProtocolError> {
    for key in GROUP_KEYS_ENC.iter() {
        if key.group == group {
            return Ok(key);
        }
    }
    Err(ProtocolError::InvalidGroup)
}

pub fn get_group_keys_from_pin(
    ctx: &Context,
    group: u16,
    pin: &[u8; 6],
) -> Result<GroupKey, ProtocolError> {
    let k_auth = ctx.k_auth(pin)?;
    let enc_keys = get_enc_group_keys(group)?;
    Ok(enc_keys.decrypt(&k_auth))
}

include!(concat!(env!("OUT_DIR"), "/secrets_generated.rs"));
