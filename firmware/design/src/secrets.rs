// TODO: automatically generate via build.rs
const BOOT_SALT_0: [u8; 32] = [0; _];

#[derive(Default)]
pub struct SymmetricKey(pub [u32; 8]);

struct AsymmetricKey([u32; 8]);

#[derive(Default)]
pub struct GroupKey {
    pub group: u16,
    sk_sign: SymmetricKey,
    pk_sign: SymmetricKey,
    sk_read: SymmetricKey,
    pk_read: SymmetricKey,
    sk_trans: SymmetricKey,
    pk_trans: SymmetricKey,
    sk_inter: SymmetricKey,
    pub pk_inter: SymmetricKey,
    t0: SymmetricKey,
    t1: SymmetricKey,
    s0: SymmetricKey,
    s1: SymmetricKey,
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
