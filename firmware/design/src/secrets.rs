use crate::protocol::ProtocolError;
use common::{AsymmetricKey, EncryptedGroupKey, SymmetricKey};

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

include!(concat!(env!("OUT_DIR"), "/secrets_generated.rs"));
