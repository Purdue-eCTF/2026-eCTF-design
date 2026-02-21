#![feature(int_from_ascii)]

use core::fmt;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use argon2::password_hash::rand_core::RngCore;
// TODO: ASLR for code and files
use argon2::{Algorithm, Argon2, Params, Version};
use bytemuck::{Pod, Zeroable};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{AeadMut, OsRng};
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::StdRng;
use rand::{Rng, RngExt, rngs::ThreadRng};
use serde::{Deserialize, de, de::Visitor};
use x25519_dalek::{PublicKey, StaticSecret};

// TODO: don't have all this stuff copy pasted in build.rs

#[derive(Copy, Clone, Default, Pod, Zeroable)]
#[repr(transparent)]
struct SymmetricKey(pub [u8; 32]);

fn public_encryption_key(secret_key: &SymmetricKey) -> SymmetricKey {
    let secret_key = StaticSecret::from(secret_key.0);
    let public_key = PublicKey::from(&secret_key);
    SymmetricKey(public_key.to_bytes())
}

fn public_signing_key(secret_key: &SymmetricKey) -> SymmetricKey {
    let secret_key = SigningKey::from_bytes(&secret_key.0);
    let public_key = VerifyingKey::from(&secret_key);
    SymmetricKey(public_key.to_bytes())
}

#[derive(Default, Clone, Copy, Deserialize, Pod, Zeroable)]
#[repr(C)]
struct GroupKey {
    pub sk_sign: SymmetricKey,
    pub pk_sign: SymmetricKey,
    pub sk_read: SymmetricKey,
    pub pk_read: SymmetricKey,
    pub sk_trans: SymmetricKey,
    pub pk_trans: SymmetricKey,
    pub sk_inter: SymmetricKey,
    pub pk_inter: SymmetricKey,
}

impl From<GroupSecretKeys> for GroupKey {
    fn from(value: GroupSecretKeys) -> Self {
        GroupKey {
            sk_sign: value.sk_sign,
            pk_sign: public_signing_key(&value.sk_sign),
            sk_read: value.sk_read,
            pk_read: public_encryption_key(&value.sk_read),
            sk_trans: value.sk_trans,
            pk_trans: public_encryption_key(&value.sk_trans),
            sk_inter: value.sk_inter,
            pk_inter: public_encryption_key(&value.sk_inter),
        }
    }
}

#[derive(Debug)]
pub struct EncryptedGroupKey {
    pub group: u16,
    pub blob: [u8; core::mem::size_of::<GroupKey>()],
    pub tag: [u8; 16],
    pub nonce: [u8; 24],
}

impl EncryptedGroupKey {
    fn from_group_keys(group: u16, group_keys: &GroupKey, key: &SymmetricKey) -> Self {
        let mut blob: [u8; core::mem::size_of::<GroupKey>()] = [0; _];
        blob.copy_from_slice(bytemuck::bytes_of(group_keys));

        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key.0));
        let nonce = XChaCha20Poly1305::generate_nonce(OsRng);

        let group_bytes = group.to_le_bytes();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &group_bytes, &mut blob)
            .expect("failed to encrypt group keys");

        EncryptedGroupKey {
            group,
            blob,
            tag: *tag.as_array().unwrap(),
            nonce: *nonce.as_array().unwrap(),
        }
    }
}

// structs which represent format of global secrets
#[derive(Default, Clone, Copy, Deserialize)]
#[repr(C)]
struct GroupSecretKeys {
    pub sk_sign: SymmetricKey,
    pub sk_read: SymmetricKey,
    pub sk_trans: SymmetricKey,
    pub sk_inter: SymmetricKey,
}

#[derive(Deserialize)]
struct GlobalSecrets {
    groups: HashMap<u16, GroupSecretKeys>,
    t0: SymmetricKey,
    t1: SymmetricKey,
    i0: SymmetricKey,
    i1: SymmetricKey,
}

// {
//   "groups": {
//     "1234": {
//       "public_keys": {
//         "pk_sign": "2d900c390212033cb2de5666b8dc30ecae0c3adeb2d207b7d5e647850d818755",
//         "pk_read": "08f304d1a9706433ec4b74bbf7172cfa5ee6e2eb25b1b2f72e76ab8212ef573a",
//         "pk_trans": "5cf0dbd9434029fdef621339d640a704922f3f9145a830a41d2a6fa022610ff7",
//         "pk_inter": "9ccb1a1a125b5881a2d7a2fb1e221e51a84c9bd8525f4502841687af21b18a1f"
//       },
//       "secret_keys": {
//         "sk_sign": "7768e1605e22fd3a8b0699f7ccf948e9117702839ed3edf5f107589722eb705b",
//         "sk_read": "ce9c72f91ae263784d24948851364088aa7b1802ffcc89695508c776bd56bff3",
//         "sk_trans": "d4fc2e581db6a2f79d24bd10d32dcbe08a44af1f03c792ff3116ce1d5918a290",
//         "sk_inter": "ca7e401a169e335149f420cd3368f8567a79c3d619f6f3bb40919b8d7951d388"
//       },
//       "shared_symmetric": {
//         "T0": "7d334421ec7bb12db1b3445e21aa3ddb01a9fe93bac04475e29590f7d484931f",
//         "T1": "635186cbc7d78a0a929bc073ab07b6991f9ecfffdcba00f176bb8a2a810ee1fe",
//         "I0": "c224a0b9778d332193158f0fc988a92ad7bd17e250dc8d8284f7fffde199a31e",
//         "I1": "0a523fe5a56721050a0c271c0e4c59089e398eafac0e30e5cf2d8d14ae2376a7"
//       }
//     },
//     "5678": {
//       "public_keys": {
//         "pk_sign": "e8842c9ecae1a43c98d5030cb0f3892c3a6973d71a82ba152fdb3a379c8fdf92",
//         "pk_read": "2c8c420ef0823aa7c2c4b94321b378f68a079d84bf453e75de606feb1799613e",
//         "pk_trans": "d7e3f1635572e3e9f50f308420baa5add33765b07ed0cb6c2ffcbb661d635672",
//         "pk_inter": "446e1ba2be3b87448b9c38018aea1eac6f6cb63d30d2b85c2e2f7820d64854f7"
//       },
//       "secret_keys": {
//         "sk_sign": "fcd2be23a3356c6845dea1af95818c06b0c7b27cc1c73b7c05fe8c525e9a6fdc",
//         "sk_read": "1e021b80fd9c2fc659b626c75095299d51569a5ba1d7bfedbd455a7797e41009",
//         "sk_trans": "94c2448351d2a5251631cd2e05f83c719dc98fca1c8c3ae22f8df57dbe4fe00c",
//         "sk_inter": "3ae884aabb722bbbaac87e989053238dfafff32531997c231bc251df65b69540"
//       },
//       "shared_symmetric": {
//         "T0": "91117b6f302ed81d8d4b6b2133611934c4106f820df7a597f6c653a43bf85a54",
//         "T1": "167c7fa9e807680d82a77b119f1d41c81740cde3ce95974451e77abda733697a",
//         "I0": "dfc3527213c3ec0b68bdd8de969b8c19dc1490935da5c37dd65ab26c93d8fa7b",
//         "I1": "b43a356d7891d2e15a0789913fb25bb8a476a30684cfe38fb7d124fddb874459"
//       }
//     }
//   }
// }

fn main() {
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=memory.x");

    // HSM_PIN='1a2b3c' -e PERMISSIONS='1234=R--:4321=RWC'
    let perms: Vec<Perms> = env!("PERMISSIONS")
        .split(":")
        .map(Perms::from_string)
        .collect();

    let secrets_file =
        &std::env::var("LOCAL_SECRETS_FILE").unwrap_or("/secrets/global.secrets".to_string());
    let mut global_secrets: GlobalSecrets = serde_json::from_str(
        &std::fs::read_to_string(secrets_file)
            .map_err(|err| format!("{err}: {secrets_file}"))
            .unwrap(),
    )
    .unwrap();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Ignore all secrets we don't have a group for
    global_secrets
        .groups
        .retain(|k, _| perms.iter().find(|perm| perm.group == *k).is_some());

    let pin = Pin::from_string(env!("HSM_PIN"));
    let salts = PinSalts::new(&pin);

    let mut encrypted_keys = Vec::new();

    // remove secrets we don't have permissions for
    for perm in perms.iter() {
        let entry = global_secrets.groups.get_mut(&perm.group).unwrap();
        let mut keys = GroupKey::from(*entry);

        if !perm.read {
            keys.pk_read = SymmetricKey([0; _]);
        }

        if !perm.write {
            keys.sk_sign = SymmetricKey([0; _]);
            keys.pk_read = SymmetricKey([0; _]);
        }

        if !perm.receive {
            keys.sk_trans = SymmetricKey([0; _]);
            keys.sk_inter = SymmetricKey([0; _]);
        }

        if !(perm.receive || perm.read || perm.write) {
            keys.pk_sign = SymmetricKey([0; _]);
            keys.pk_trans = SymmetricKey([0; _]);
            keys.pk_inter = SymmetricKey([0; _]);
        }

        encrypted_keys.push(EncryptedGroupKey::from_group_keys(
            perm.group,
            &keys,
            &salts.k_auth,
        ));
    }

    let secrets_file = generate_secrets(&salts, &global_secrets, &encrypted_keys);
    std::fs::write(
        out_dir.join("secrets_generated.rs"),
        secrets_file.as_bytes(),
    )
    .expect("failed to write generated secrets");
}

fn generate_secrets(
    pin_salts: &PinSalts,
    global_keys: &GlobalSecrets,
    group_keys: &[EncryptedGroupKey],
) -> String {
    let encrypted_keys = group_keys
        .iter()
        .map(|group_key| format!("{:?}", group_key))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "// This file was automatically generated by build.rs
pub const ARGON_M_COST: u32 = {}; // memory cost in kb
pub const ARGON_P_COST: u32 = {}; // parallelism costs

// PLACEHOLDER: Time cost (iterations) for Boot Salt 1 generation
pub const T_COST_BOOT: u32 = {};

// Time cost for PIN Salt derivation
pub const T_COST_PIN: u32 = {};

// Time cost for K_auth
pub const T_COST_K_AUTH: u32 = {};

pub const BOOT_SALT_0: [u8; 32] = {:?};

// T0
pub const TRANSFER_SEND: SymmetricKey = SymmetricKey({:?});
// T1
pub const TRANSFER_RECV: SymmetricKey = SymmetricKey({:?});

// I0
pub const INTERROGATE_SEND: SymmetricKey = SymmetricKey({:?});
// I1
pub const INTERROGATE_RECV: SymmetricKey = SymmetricKey({:?});

// TODO: must be sorted by group
pub const GROUP_KEYS_ENC: [EncryptedGroupKey; {}] = [{}];
",
        ARGON_M_COST,
        ARGON_P_COST,
        T_COST_BOOT,
        T_COST_PIN,
        T_COST_K_AUTH,
        pin_salts.boot_salt_0,
        global_keys.t0.0,
        global_keys.t1.0,
        global_keys.i0.0,
        global_keys.i1.0,
        group_keys.len(),
        encrypted_keys,
    )
}

struct Perms {
    group: u16,
    read: bool,
    write: bool,
    receive: bool,
}

impl Perms {
    fn from_string(s: &str) -> Self {
        let (group, perms) = s.split_once("=").unwrap();
        Self {
            group: group.parse().unwrap(),
            read: perms.chars().nth(0) == Some('R'),
            write: perms.chars().nth(0) == Some('W'),
            receive: perms.chars().nth(0) == Some('C'),
        }
    }
}

#[repr(transparent)]
struct Pin([u8; 6]);
impl Pin {
    fn from_string(s: &str) -> Self {
        assert!(s.len() == 6);
        let mut arr = [0; 6];
        arr.copy_from_slice(s.as_bytes());

        Self(arr)
    }
}

const ARGON_M_COST: u32 = 8;
const ARGON_P_COST: u32 = 1;
// TODO: figure out these costs
const T_COST_BOOT: u32 = 1;
const T_COST_PIN: u32 = 1;
const T_COST_K_AUTH: u32 = 1;

// TODO: emit this in secrets_generated
const DERIVE_SALT: &[u8] = b"ectf-deriv";

fn derive_next_salt(input: &[u8], t_cost: u32) -> Salt {
    let params = Params::new(
        ARGON_M_COST,
        t_cost,
        ARGON_P_COST,
        Some(std::mem::size_of::<Salt>()),
    )
    .expect("Argon Params Invalid");

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out: Salt = [0; _];
    argon
        .hash_password_into(&input, DERIVE_SALT, &mut out)
        .expect("deriving salt failed");
    out
}

type Salt = [u8; 32];
struct PinSalts {
    boot_salt_0: Salt,
    boot_salt_1: Salt,
    pin_salt: Salt,
    k_auth: SymmetricKey,
}

impl PinSalts {
    fn new(pin: &Pin) -> Self {
        let mut boot_salt_0: Salt = [0; _];
        OsRng.fill_bytes(&mut boot_salt_0);

        let boot_salt_1 = derive_next_salt(&boot_salt_0, T_COST_BOOT);
        let pin_salt = derive_next_salt(&boot_salt_1, T_COST_PIN);

        let mut pin_buffer = [0; 32 + 6];
        pin_buffer[..6].copy_from_slice(&pin.0);
        pin_buffer[6..].copy_from_slice(&pin_salt);
        let k_auth = derive_next_salt(&pin_buffer, T_COST_K_AUTH);

        PinSalts {
            boot_salt_0,
            boot_salt_1,
            pin_salt,
            k_auth: SymmetricKey(k_auth),
        }
    }
}

// The rest of the file is traits to parse/format everything

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.0))
    }
}

struct SymmetricKeyParser;
impl SymmetricKeyParser {
    fn fromhex(s: &str) -> Option<SymmetricKey> {
        if s.len() != 64 {
            return None;
        }

        let mut value = [0; 32];

        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let Ok(hex) = u8::from_ascii_radix(pair, 16) else {
                return None;
            };
            value[i] = hex;
        }

        Some(SymmetricKey(value))
    }
}

impl<'de> Visitor<'de> for SymmetricKeyParser {
    type Value = SymmetricKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("64-character (32-byte) hex string")
    }

    fn visit_str<E>(self, value: &str) -> Result<SymmetricKey, E>
    where
        E: de::Error,
    {
        SymmetricKeyParser::fromhex(value).ok_or(de::Error::invalid_value(
            de::Unexpected::Str(value),
            &"A hex string",
        ))
    }
}

impl<'de> Deserialize<'de> for SymmetricKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(SymmetricKeyParser)
    }
}
