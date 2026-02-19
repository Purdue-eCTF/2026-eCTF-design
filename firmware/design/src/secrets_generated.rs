// TODO: automatically generate via build.rs
use crate::secrets::{EncryptedGroupKey, SymmetricKey};

pub const BOOT_SALT_0: [u8; 32] = [0; _];
pub const PIN: [u8; 6] = [0; _];

// TODO: which one is t0 vs t1?
pub const TRANSFER_SEND: SymmetricKey = SymmetricKey([0; _]);
pub const TRANSFER_RECV: SymmetricKey = SymmetricKey([0; _]);

// TODO: which one is i0 vs i1?
pub const INTERROGATE_SEND: SymmetricKey = SymmetricKey([0; _]);
pub const INTERROGATE_RECV: SymmetricKey = SymmetricKey([0; _]);

// TODO: must be sorted by group
pub const GROUP_KEYS_ENC: [EncryptedGroupKey; 1] = [EncryptedGroupKey {
    group: 0x0000,
    blob: [0; _],
    nonce: [0; _],
    tag: [0; _],
}];
