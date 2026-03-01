use core::fmt;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use argon2::password_hash::rand_core::RngCore;
// TODO: ASLR for code and files
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::OsRng;
use common::{EncryptedGroupKey, GroupKey, SymmetricKey};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

/// From a private key, generate its public key with x25519_dalek. This is for asymmetric
/// encryption.
fn public_encryption_key(secret_key: &SymmetricKey) -> SymmetricKey {
    let secret_key = StaticSecret::from(secret_key.0);
    let public_key = PublicKey::from(&secret_key);
    SymmetricKey(public_key.to_bytes())
}

/// From a private signing key, generate its public key. This is for signature verification.
fn public_signing_key(secret_key: &SymmetricKey) -> SymmetricKey {
    let secret_key = common::expand_private_key(&secret_key.0);
    let public_key = VerifyingKey::from(&secret_key);
    SymmetricKey(public_key.to_bytes())
}

impl From<GroupSecretKeys> for GroupKey {
    /// Retrieve the set of a group keys that are stored encrypted on flash.
    fn from(value: GroupSecretKeys) -> Self {
        GroupKey {
            sk_sign: Some(value.sk_sign),
            sk_read: Some(value.sk_read),
            pk_read: Some(public_encryption_key(&value.sk_read)),
            sk_trans: Some(value.sk_trans),
            k_uuid: Some(value.k_uuid),
        }
    }
}

// structs which represent format of global secrets
#[derive(Default, Debug, Clone, Copy, Deserialize)]
#[repr(C)]
struct GroupSecretKeys {
    /// The private key for signature generation.
    pub sk_sign: SymmetricKey,
    /// The private key used in the read function.
    pub sk_read: SymmetricKey,
    /// The private key used in the transfer function.
    pub sk_trans: SymmetricKey,
    /// The private key used in the interrogate function.
    pub k_inter: SymmetricKey,
    /// The private key used to protect UUIDs.
    pub k_uuid: SymmetricKey,
}
/// Struct abstracting all the group keys, symmetric keys, and a salt for asymmetric encryption,
/// that are on the board.
#[derive(Deserialize, Debug)]
struct GlobalSecrets {
    groups: HashMap<u16, GroupSecretKeys>,
    t0: SymmetricKey,
    t1: SymmetricKey,
    i0: SymmetricKey,
    i1: SymmetricKey,
    pub_encrypt_salt: SymmetricKey,
}

fn main() {
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-env-changed=BUILD_SEED");

    println!("cargo:rustc-link-arg=-Xlinker");
    println!("cargo:rustc-link-arg=--print-memory-usage");

    // HSM_PIN='1a2b3c' -e PERMISSIONS='1234=R--:4321=RWC'
    // Retrieve all groups and their permissions.
    let perms: Vec<Perms> = env!("PERMISSIONS")
        .split(":")
        .map(Perms::from_string)
        .collect();

    // Retrieve all secrets (keys) from the pregenerated file.
    let secrets_file =
        &std::env::var("LOCAL_SECRETS_FILE").unwrap_or("/secrets/global.secrets".to_string());
    let mut global_secrets: GlobalSecrets = serde_json::from_str(
        &std::fs::read_to_string(secrets_file)
            .map_err(|err| format!("{err}: {secrets_file}"))
            .unwrap(),
    )
    .unwrap();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Ignore all secrets that there isn't a group for
    global_secrets.groups.retain(|k, _| {
        perms
            .iter()
            .find(|perm| (perm.group == *k) && perm.has_any_perms())
            .is_some()
    });

    // Retrieve pin to generate pin salts
    let pin = Pin::from_string(env!("HSM_PIN"));
    let salts = PinSalts::new(&pin);

    let mut encrypted_keys = Vec::new();
    let mut copy_perm_groups = Vec::new();

    // Remove secrets that there aren't permissions for
    for perm in perms.iter() {
        // TODO: permissions for nonexistent groups? how does this happen?
        let Some(entry) = global_secrets.groups.get_mut(&perm.group) else {
            println!("wanted permissions for {perm:?}, but did not find in global secrets");
            println!("{:?}", global_secrets);
            continue;
        };
        let mut keys = GroupKey::from(*entry);
        let pk_sign = public_signing_key(&keys.sk_sign.unwrap());
        let pk_trans = public_encryption_key(&keys.sk_trans.unwrap());
        let k_inter = entry.k_inter;

        // Read permission gates access to the read-decryption private key.
        if !perm.read {
            keys.sk_read = None;
        }

        // Write permission gates signing and the public read-encryption key used
        // to encrypt file contents at write time.
        if !perm.write {
            keys.sk_sign = None;
            keys.pk_read = None;
        }

        if perm.receive {
            copy_perm_groups.push(perm.group);
        } else {
            keys.sk_trans = None;
        }

        if !(perm.write || perm.receive) {
            keys.k_uuid = None;
        }

        encrypted_keys.push(EncryptedGroupKey::from_group_keys(
            &mut OsRng,
            perm.group,
            &keys,
            &salts.k_auth,
            pk_sign,
            pk_trans,
            k_inter,
        ));
    }
    encrypted_keys.sort_by_key(|k| k.group);

    let secrets_file =
        generate_secrets(&salts, &global_secrets, &encrypted_keys, &copy_perm_groups);
    std::fs::write(
        out_dir.join("secrets_generated.rs"),
        secrets_file.as_bytes(),
    )
    .expect("failed to write generated secrets");
}

/// Using the generated secrets, return a formatted String with all of the information ready for use in the firmware.
/// Output is included in secrets.rs.
fn generate_secrets(
    pin_salts: &PinSalts,
    global_keys: &GlobalSecrets,
    group_keys: &[EncryptedGroupKey],
    copy_perm_grops: &[u16],
) -> String {
    assert!(group_keys.is_sorted_by_key(|k| k.group));

    let stack_canary = OsRng.next_u32();

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
// TODO: make in special section of flash
pub const BOOT_SALT_1: [u8; 32] = {:?};

pub const K_AUTH_SALT: [u8; 32] = {:?};
pub const K_AUTH_HASH: [u8; 32] = {:?};

// T0
pub const TRANSFER_SEND: SymmetricKey = SymmetricKey({:?});
// T1
pub const TRANSFER_RECV: SymmetricKey = SymmetricKey({:?});

// I0
pub const INTERROGATE_SEND: SymmetricKey = SymmetricKey({:?});
// I1
pub const INTERROGATE_RECV: SymmetricKey = SymmetricKey({:?});

// salt for argon derivation
pub const DERIVE_SALT: &[u8] = &{:?};
// salt for blake2 derivation
pub const PUB_ENCRYPT_SALT: [u8; 32] = {:?};

// TODO: must be sorted by group
pub const GROUP_KEYS_ENC: [EncryptedGroupKey; {}] = [{}];

pub const COPY_PERM_GROUPS: [u16; {}] = {:?};

pub const STACK_CANARY_START_VALUE: usize = {};
",
        ARGON_M_COST,
        ARGON_P_COST,
        T_COST_BOOT,
        T_COST_PIN,
        T_COST_K_AUTH,
        pin_salts.boot_salt_0,
        pin_salts.boot_salt_1,
        pin_salts.k_auth_salt,
        pin_salts.k_auth_hash,
        global_keys.t0.0,
        global_keys.t1.0,
        global_keys.i0.0,
        global_keys.i1.0,
        &DERIVE_SALT,
        global_keys.pub_encrypt_salt.0,
        group_keys.len(),
        encrypted_keys,
        copy_perm_grops.len(),
        copy_perm_grops,
        stack_canary,
    )
}

/// Container for a group and its permissions.
#[derive(Debug)]
struct Perms {
    group: u16,
    read: bool,
    write: bool,
    receive: bool,
}

impl Perms {
    /// Retrieve permissions for a group from a string input.
    fn from_string(s: &str) -> Self {
        let (group, perms) = s.split_once("=").unwrap();
        Self {
            group: u16::from_str_radix(group, 16).unwrap(),
            read: perms.chars().nth(0) == Some('R'),
            write: perms.chars().nth(1) == Some('W'),
            receive: perms.chars().nth(2) == Some('C'),
        }
    }

    fn has_any_perms(&self) -> bool {
        // read perm is useless without write or receive, so discard if only read
        self.write || self.receive
    }
}

/// Container for the pin.
#[repr(transparent)]
struct Pin([u8; 6]);
impl Pin {
    /// Retrieve the pin from a string input.
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
// approx. t (ms) = 21 * cost + 10
const T_COST_BOOT: u32 = 45; // ~950ms
const T_COST_PIN: u32 = 185; // ~3875ms
const T_COST_K_AUTH: u32 = 1;

const DERIVE_SALT: &[u8] = b"ectf-deriv";

/// Tunes and uses Argon2id to generate a new hash for a specified cost that changes the amount of
/// time the hashing process will take.
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
        .hash_password_into(input, DERIVE_SALT, &mut out)
        .expect("deriving salt failed");
    out
}

/// Blake hash with a single salt.
fn blake_hash(input: &[u8], salt: &Salt) -> [u8; 32] {
    let mut blake_hasher = Blake2s256::new();
    blake_hasher.update(input);
    blake_hasher.update(salt);
    *blake_hasher.finalize().as_array().unwrap()
}

type Salt = [u8; 32];
/// TODO (is this necessary) A struct containing all salts and keys associated with the pin.
struct PinSalts {
    /// Random bytes stored in flash, to be used to create boot salt 1.
    boot_salt_0: Salt,
    /// The hashed boot salt 0. TODO (should this be included) Stored in flash, wiped before every
    /// operation and restored after.
    boot_salt_1: Salt,
    /// The hashed boot salt 1, which should only be stored in RAM.
    pin_salt: Salt,
    /// A key created by hashing a provided pin with the pin salt.
    k_auth: SymmetricKey,
    /// Random bytes stored in flash.
    k_auth_salt: Salt,
    /// A hash created with k_auth and k_auth_salt used to verify a generated k_auth.
    k_auth_hash: [u8; 32],
}

impl PinSalts {
    /// Generate the pin salts to populate the struct fields, one after the other.
    fn new(pin: &Pin) -> Self {
        let mut boot_salt_0: Salt = [0; _];
        OsRng.fill_bytes(&mut boot_salt_0);

        let boot_salt_1 = derive_next_salt(&boot_salt_0, T_COST_BOOT);
        let pin_salt = derive_next_salt(&boot_salt_1, T_COST_PIN);

        let mut pin_buffer = [0; 32 + 6];
        pin_buffer[..6].copy_from_slice(&pin.0);
        pin_buffer[6..].copy_from_slice(&pin_salt);
        let k_auth = derive_next_salt(&pin_buffer, T_COST_K_AUTH);

        let mut k_auth_salt: Salt = [0; _];
        OsRng.fill_bytes(&mut k_auth_salt);
        let k_auth_hash = blake_hash(&k_auth, &k_auth_salt);

        PinSalts {
            boot_salt_0,
            boot_salt_1,
            pin_salt,
            k_auth: SymmetricKey(k_auth),
            k_auth_salt,
            k_auth_hash,
        }
    }
}

impl fmt::Debug for Pin {
    /// Format to write pin.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.0))
    }
}
