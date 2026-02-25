use crate::{context::Context, protocol::ProtocolError};
use common::{EncryptedGroupKey, GroupKey, SymmetricKey};

/// Returns the stored keys for a group.
/// pk_sign, pk_trans, and pk_inter are accessible.
/// Other keys must be decrypted using k_auth,
/// which is derived from the PIN.
pub fn get_enc_group_keys(group: u16) -> Result<&'static EncryptedGroupKey, ProtocolError> {
    for key in GROUP_KEYS_ENC.iter() {
        if key.group == group {
            return Ok(key);
        }
    }
    Err(ProtocolError::InvalidGroup)
}

/// Derives k_auth from the PIN to decrypt and return the secret keys for a group.
pub fn get_group_keys_from_pin(
    ctx: &Context,
    group: u16,
    pin: &[u8; 6],
) -> Result<GroupKey, ProtocolError> {
    let k_auth = ctx.k_auth(pin)?;
    let enc_keys = get_enc_group_keys(group)?;
    Ok(enc_keys.decrypt(&k_auth))
}

// Add constant argon params, salts, hashes, and group keys at build time. See design/build.rs.
include!(concat!(env!("OUT_DIR"), "/secrets_generated.rs"));
