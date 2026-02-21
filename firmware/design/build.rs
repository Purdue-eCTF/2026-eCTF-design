#![feature(int_from_ascii)]

use core::fmt;
use std::collections::HashMap;

// TODO: ASLR for code and files
use argon2::Argon2;
use rand::{Rng, RngExt, rngs::ThreadRng};
use serde::{Deserialize, de, de::Visitor};

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
struct SymmetricKey(pub [u8; 32]);

#[derive(Default, Clone, Copy, Deserialize)]
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
    pub t0: SymmetricKey,
    pub t1: SymmetricKey,
    pub i0: SymmetricKey,
    pub i1: SymmetricKey,
}

pub struct EncryptedGroupKey {
    pub group: u16,
    pub blob: [u8; core::mem::size_of::<GroupKey>()],
    pub tag: [u8; 16],
    pub nonce: [u8; 24],
}

#[derive(Deserialize)]
struct GlobalSecrets {
    groups: HashMap<u16, GroupKey>,
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

    // Ignore all secrets we don't have a group for
    global_secrets
        .groups
        .retain(|k, _| perms.iter().find(|perm| perm.group == *k).is_some());

    // remove secrets we don't have permissions for
    for perm in perms.iter() {
        let entry = global_secrets.groups.get_mut(&perm.group).unwrap();
        if !perm.write {
            entry.sk_sign = SymmetricKey([0; _]);
            entry.pk_read = SymmetricKey([0; _]);
        }
        if !(perm.receive || perm.read || perm.write) {
            entry.pk_sign = SymmetricKey([0; _]);
        }

        if !perm.receive {
            entry.sk_read = SymmetricKey([0; _]);
        }

        if !perm.receive {
            // TODO: what...
            entry.sk_write = SymmetricKey([0; _]);
        }
    }
    let mut rng = ThreadRng::default();
    let boot_salt = gen_bytes(&mut rng, 32);
    let pin = Pin::from_string(env!("HSM_PIN"));

    print!("{}", generate_secrets(&boot_salt, pin, &[]));
}

fn gen_bytes(rng: &mut impl Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    rng.fill_bytes(&mut v);
    v
}

fn generate_secrets(boot_salt_0: &[u8], pin: Pin, group_keys: &[EncryptedGroupKey]) -> String {
    format!(
        "// This file was automatically generated by build.rs
use crate::secrets::{{EncryptedGroupKey, SymmetricKey}};

pub const BOOT_SALT_0: [u8; 32] = {:?};
pub const PIN: [u8; 6] = {:?};

// TODO: must be sorted by group
pub const GROUP_KEYS_ENC: [EncryptedGroupKey; {}] = [EncryptedGroupKey {{
    group: 0x0000,
    blob: [0; _],
    nonce: [0; _],
    tag: [0; _],
}}];
",
        boot_salt_0,
        pin,
        group_keys.len()
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
