use bytemuck::{Pod, Zeroable};

use crate::{
    Context,
    crypto::{
        self, PubKeyMetadata, SymmetricMetadata, decrypt_payload_pub, unwrap_symmetric_message,
    },
    file::{File, FileName},
    message::{Message, MessagePort, Opcode},
    protocol::{ProtocolError, TransferM0Encrypted},
    secrets::{self, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ListenError {
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Invalid file")]
    InvalidFile,
    #[error("Invalid opcode")]
    InvalidOpcode,
}
#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]

/// File metadata included in response to Interrogate from neighbor HSM.
/// Protected info should be encrypted before send.
pub struct InterrogateFile {
    // group must not be u16 because it is ub to take reference to u16 in packed struct with potentially less alignment
    pub group_bytes: [u8; 2],
    pub protected: InterrogateFileProtected,
}

impl InterrogateFile {
    /// Retrieve group id from the struct.
    pub fn group(&self) -> u16 {
        u16::from_le_bytes(self.group_bytes)
    }

    /// Set group id in the struct.
    pub fn set_group(&mut self, group: u16) {
        self.group_bytes = group.to_le_bytes();
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]

/// File metadata that should be encrypted before send.
/// Included in response to Interrogate from neighbor HSM
pub struct InterrogateFileProtected {
    pub slot: u8,
    pub name: FileName,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]

/// Encrypted metadata for a file and associated metadata for decryption.
/// Sent in response to Interrogate from neighbor HSM
pub struct EncryptedInterrogateInfo {
    pub file: InterrogateFile,
    pub metadata: PubKeyMetadata,
}

impl EncryptedInterrogateInfo {
    /// Helper function to encrypt interrogation information with a public key.
    pub fn encrypt(&mut self, public_key: &[u8; 32]) -> Result<(), ProtocolError> {
        let Self {
            file:
                InterrogateFile {
                    group_bytes,
                    protected,
                },
            metadata,
            ..
        } = self;

        *metadata =
            PubKeyMetadata::encrypt(bytemuck::bytes_of_mut(protected), public_key, group_bytes)?;

        Ok(())
    }

    /// Helper function to decrypt interrogation information with a decrypted private key.
    pub fn decrypt(&mut self, secret_key: &[u8; 32]) -> Result<(), ProtocolError> {
        let Self {
            file:
                InterrogateFile {
                    group_bytes,
                    protected,
                },
            metadata,
            ..
        } = self;

        decrypt_payload_pub(
            bytemuck::bytes_of_mut(protected),
            &metadata.gn,
            &metadata.nonce,
            &metadata.tag,
            secret_key,
            group_bytes,
        )?;

        Ok(())
    }
}

#[inline]
/// Handle a command received in listen mode.
pub fn recv(ctx: &mut Context, opcode: Opcode, body: &mut [u8]) -> Result<(), ListenError> {
    match opcode {
        Opcode::Interrogate => respond_interrogate(ctx, body),
        Opcode::Receive => respond_transfer(ctx, body).unwrap(),
        _ => return Err(ListenError::InvalidOpcode),
    };
    Ok(())
}

/// Handle an interrogate command from a neighbor HSM, received while in listen mode.
fn respond_interrogate(ctx: &mut Context, body: &mut [u8]) {
    // Expect body = Enc_I0(Group1 || Group2 || ... || GroupN) || SM
    let i0 = INTERROGATE_SEND.0;

    let msg = unwrap_symmetric_message(body, &i0, &[Opcode::Interrogate.into()]).unwrap();

    // msg = Group1 || Group2 || ... || GroupN

    // next we will create M1 = Enc_I1(
    //    (EncFile1 || PKM1) ||
    //    (EncFile2 || PKM2) ||
    // ... ||
    //    (EncFileN || PKMN) ||
    //    SM
    // )
    // EncFilei = group || Enc_pk_inter(slot || name)

    // size of EncFilei || PKMi
    const ENTRY_SIZE: usize = size_of::<EncryptedInterrogateInfo>();

    // allocate a payload buffer of the maximum size and write the ciphertext into it
    let mut payload = [0; 8 * ENTRY_SIZE + size_of::<crypto::SymmetricMetadata>()];

    // list: the encrypted InterrogateFiles
    // sm_bytes: contains SM
    let (list, _) = payload.split_at_mut(8 * ENTRY_SIZE);
    let mut count = 0;
    for chunk in msg.chunks_exact(2) {
        let bytes: &[u8; 2] = chunk.try_into().unwrap();
        let group = u16::from_le_bytes(*bytes);

        for i in 0..8 {
            let file = ctx.files[i].get().unwrap();
            // check if the slot is full and the group id matches
            let metadata = &file.protected;
            // if a valid file matches the group, add it to the list
            if file.is_full() && metadata.group == group {
                let group_keys = secrets::get_enc_group_keys(group).unwrap();
                if crypto::verify_signature(file, &group_keys.pk_sign.0).is_err() {
                    continue;
                }

                // get location of the next entry in list
                let entry = &mut list[count * ENTRY_SIZE..(count + 1) * ENTRY_SIZE];
                let (content, pkm) = entry.split_at_mut(size_of::<InterrogateFile>());

                // copy the InterrogateFile to the start of the entry
                let ifile: &mut InterrogateFile = bytemuck::from_bytes_mut(content);
                *ifile = InterrogateFile {
                    group_bytes: metadata.group.to_le_bytes(),
                    protected: InterrogateFileProtected {
                        slot: i as u8,
                        name: metadata.name,
                    },
                };
                let pkm: &mut crypto::PubKeyMetadata = bytemuck::from_bytes_mut(pkm);
                let key = group_keys.pk_inter.0;

                // encrypt just the slot and filename
                // write G^n, nonce, tag to PKM at the end of entry
                // HSM1 needs to read group in order to get the correct key
                let _ = crypto::encrypt_payload_pub(
                    bytemuck::bytes_of_mut(&mut ifile.protected),
                    &mut pkm.gn,
                    &mut pkm.nonce,
                    &mut pkm.tag,
                    &key,
                    &metadata.group.to_le_bytes(),
                )
                .unwrap();
                count += 1;
            }
        }
    }

    let i1 = INTERROGATE_RECV.0;

    let body_size = count * ENTRY_SIZE;

    let (body, sm_bytes) = payload.split_at_mut(body_size);
    let sm: &mut crypto::SymmetricMetadata =
        bytemuck::from_bytes_mut(&mut sm_bytes[..size_of::<crypto::SymmetricMetadata>()]);

    // encrypt the part of buffer that was used
    let _ = crypto::encrypt_payload_symmetric(
        body,
        &mut sm.nonce,
        &mut sm.tag,
        &i1,
        &[Opcode::Interrogate.into()],
    )
    .unwrap();

    let payload_size = body_size + size_of::<crypto::SymmetricMetadata>();
    Message::write(
        Opcode::Interrogate,
        MessagePort::UART1,
        &payload[..payload_size],
    )
    .unwrap();
}

/// Handle a receive command from a neighbor HSM, received while in listen mode.
fn respond_transfer(ctx: &mut Context, body: &mut [u8]) -> Result<(), ListenError> {
    if body.len() != size_of::<TransferM0Encrypted>() {
        return Err(ListenError::InvalidMessageLength);
    }
    let enc: &TransferM0Encrypted = bytemuck::from_bytes(body);
    let m0 = enc.decrypt().unwrap();

    let slot: usize = m0.slot as usize;

    if slot > 7 {
        return Err(ListenError::InvalidFile);
    }

    let file_src = ctx.files[slot].get().unwrap();
    if !file_src.is_full() {
        return Err(ListenError::InvalidFile);
    }

    // TODO: check that all instances where we use &PIN are valid
    let group_keys = secrets::get_enc_group_keys(file_src.protected.group).unwrap();
    if crypto::verify_signature(file_src, &group_keys.pk_sign.0).is_err() {
        return Err(ListenError::InvalidFile);
    }

    let group_id_bytes = file_src.protected.group.to_le_bytes();

    // we will create M1 = Enc_T1(Enc_pk_trans(file) || PKM || group id) || SM
    // create a payload buffer of the maximum size
    let mut payload = [0; size_of::<File>()
        + size_of::<PubKeyMetadata>()
        + size_of::<u16>()
        + size_of::<SymmetricMetadata>()];
    let payload_len = payload.len();

    let (file, rest) = payload.split_at_mut(size_of::<File>());
    let (pub_key_meta, rest) = rest.split_at_mut(size_of::<PubKeyMetadata>());
    let pub_key_meta: &mut PubKeyMetadata = bytemuck::from_bytes_mut(pub_key_meta);
    let group_id = &mut rest[..size_of::<u16>()];

    // copy the file to payload
    file.copy_from_slice(&bytemuck::bytes_of(file_src));

    // encrypt file with pk trans
    *pub_key_meta = PubKeyMetadata::encrypt(file, &group_keys.pk_trans.0, &group_id_bytes).unwrap();

    // write associated data
    group_id.copy_from_slice(&group_id_bytes);

    let (data, symmetric_meta) = payload.split_at_mut(payload_len - size_of::<SymmetricMetadata>());
    let symmetric_meta: &mut SymmetricMetadata = bytemuck::from_bytes_mut(symmetric_meta);

    // encrypt file with T1
    *symmetric_meta =
        SymmetricMetadata::encrypt(data, &TRANSFER_RECV.0, &[Opcode::Receive.into()]).unwrap();

    Message::write(Opcode::Receive, MessagePort::UART1, &payload).unwrap();

    Ok(())
}
