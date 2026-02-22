use crate::context::Context;
use common::{EncryptedGroupKey, GroupKey, SymmetricKey};

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
