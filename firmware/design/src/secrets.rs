// TODO: automatically generate via build.rs
const BOOT_SALT_0: [u8; 32] = [0; _];

#[derive(Default)]
pub struct SymmetricKey(pub [u8; 32]);

pub struct AsymmetricKey([u8; 32]);

#[derive(Default)]
pub struct GroupKey {
    pub group: u16,
    pub sk_sign: SymmetricKey,
    pub pk_sign: SymmetricKey,
    pub sk_read: SymmetricKey,
    pub pk_read: SymmetricKey,
    pub sk_trans: SymmetricKey,
    pub pk_trans: SymmetricKey,
    pub sk_inter: SymmetricKey,
    pub pk_inter: SymmetricKey,
    pub t0: SymmetricKey,
    pub t1: SymmetricKey,
    pub s0: SymmetricKey,
    pub s1: SymmetricKey,
}

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
    t0: SymmetricKey([0; _]),
    t1: SymmetricKey([0; _]),
    s0: SymmetricKey([0; _]),
    s1: SymmetricKey([0; _]),
}];
