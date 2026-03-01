use crate::protocol::ProtocolError;
use common::{EncryptedGroupKey, SymmetricKey};

pub fn get_enc_group_keys(group: u16) -> Result<&'static EncryptedGroupKey, ProtocolError> {
    for key in GROUP_KEYS_ENC.iter() {
        if key.group == group {
            return Ok(key);
        }
    }
    Err(ProtocolError::InvalidGroup)
}

include!(concat!(env!("OUT_DIR"), "/secrets_generated.rs"));
