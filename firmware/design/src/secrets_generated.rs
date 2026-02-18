// TODO: automatically generate via build.rs
use crate::secrets::{GroupKey, SymmetricKey};

const BOOT_SALT_0: [u8; 32] = [0; _];

// TODO: which one is t0 vs t1?
pub const TRANSFER_SEND: SymmetricKey = SymmetricKey([0; _]);
pub const TRANSFER_RECV: SymmetricKey = SymmetricKey([0; _]);

// TODO: which one is i0 vs i1?
pub const INTERROGATE_SEND: SymmetricKey = SymmetricKey([0; _]);
pub const INTERROGATE_RECV: SymmetricKey = SymmetricKey([0; _]);

pub const GROUP_KEYS: [GroupKey; 1] = [GroupKey {
    group: 0x0000,
    sk_sign: SymmetricKey([0; _]),
    pk_sign: SymmetricKey([0; _]),
    sk_read: SymmetricKey([0; _]),
    pk_read: SymmetricKey([0; _]),
    sk_trans: SymmetricKey([0; _]),
    pk_trans: SymmetricKey([0; _]),
    sk_inter: SymmetricKey([0; _]),
    pk_inter: SymmetricKey([0; _]),
}];
