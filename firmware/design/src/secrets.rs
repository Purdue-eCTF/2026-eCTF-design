use crate::secrets_generated::GROUP_KEYS;

#[derive(Default)]
pub struct SymmetricKey(pub [u8; 32]);

#[derive(Default)]
pub struct GroupKey {
    pub group: u16,
    pub sk_sign: SymmetricKey,
    pub pk_sign: SymmetricKey,
    pub sk_read: SymmetricKey,
    pub pk_read: SymmetricKey,
    pub sk_trans: SymmetricKey, // TODO: why is this unused?
    pub pk_trans: SymmetricKey,
    pub sk_inter: SymmetricKey,
    pub pk_inter: SymmetricKey,
}

// TODO: Placeholder function until using the pin to decrypt keys is implemented
pub fn get_group_keys_from_pin(group: u16, _pin: &[u8; 6]) -> Result<&'static GroupKey, ()> {
    let mut r = Err(());
    for key in GROUP_KEYS.iter() {
        if key.group == group {
            r = Ok(key);
        }
    }
    r
}

pub fn get_group_keys(group: u16) -> Result<&'static GroupKey, ()> {
    let mut r = Err(());
    for key in GROUP_KEYS.iter() {
        if key.group == group {
            r = Ok(key);
        }
    }
    r
}
