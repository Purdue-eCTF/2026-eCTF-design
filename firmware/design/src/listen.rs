use bytemuck::{Pod, Zeroable};

use crate::{
    Context, crypto,
    file::{self, File, FileName},
    message::{Message, MessagePort, Opcode},
    protocol::TransferM0Encrypted,
    secrets,
    secrets_generated::{INTERROGATE_RECV, INTERROGATE_SEND, PIN, TRANSFER_RECV},
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
pub struct InterrogateFile {
    pub group: u16,
    pub protected: InterrogateFileProtected,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct InterrogateFileProtected {
    pub slot: u8,
    pub name: FileName,
}

pub fn recv(ctx: &mut Context, opcode: Opcode, body: &mut [u8]) -> Result<(), ListenError> {
    match opcode {
        Opcode::Interrogate => respond_interrogate(ctx, body),
        Opcode::Receive => respond_transfer(ctx, body).unwrap(),
        _ => return Err(ListenError::InvalidOpcode),
    };
    Ok(())
}

fn respond_interrogate(ctx: &mut Context, body: &mut [u8]) {
    // Expect body = Enc_I0(Group1 || Group2 || ... || GroupN) || SM
    let i0 = INTERROGATE_SEND.0;

    // split them
    let (ct, sm_recv_bytes) =
        body.split_at_mut(body.len() - size_of::<crypto::SymmetricMetadata>());
    let sm_recv: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(sm_recv_bytes);
    let msg = crypto::decrypt_payload_symmetric(
        ct,
        &sm_recv.nonce,
        &sm_recv.tag,
        &i0,
        &[Opcode::Interrogate.into()],
    )
    .unwrap();

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
    const ENTRY_SIZE: usize = size_of::<InterrogateFile>() + size_of::<crypto::PubKeyMetadata>();

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
                let group_keys = secrets::get_group_keys_from_pin(ctx, group, &PIN).unwrap();
                if crypto::verify_signature(file, &group_keys.pk_sign.0).is_err() {
                    continue;
                }

                // get location of the next entry in list
                let entry = &mut list[count * ENTRY_SIZE..(count + 1) * ENTRY_SIZE];
                let (content, pkm) = entry.split_at_mut(size_of::<InterrogateFile>());

                // copy the InterrogateFile to the start of the entry
                let ifile: &mut InterrogateFile = bytemuck::from_bytes_mut(content);
                *ifile = InterrogateFile {
                    group: metadata.group,
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
                )
                .unwrap();
                count += 1;
            }
        }
    }

    let i1 = INTERROGATE_RECV.0;

    let body_size = count * ENTRY_SIZE;

    let (_, sm_bytes) = payload.split_at_mut(body_size);
    let sm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(sm_bytes);

    // encrypt the part of buffer that was used
    let _ = crypto::encrypt_payload_symmetric(
        &mut body[..body_size],
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
        &body[..payload_size],
    )
    .unwrap();
}

fn respond_transfer(ctx: &mut Context, body: &mut [u8]) -> Result<(), ListenError> {
    if body.len() != size_of::<TransferM0Encrypted>() {
        return Err(ListenError::InvalidMessageLength);
    }
    let enc: &TransferM0Encrypted = bytemuck::from_bytes(body);
    let m0 = enc.decrypt().unwrap();

    let slot: usize = m0.slot as usize;
    let group = m0.group;

    if slot > 7 {
        return Err(ListenError::InvalidFile);
    }

    let file = ctx.files[slot].get().unwrap();
    if !file.is_full() || file.protected.group != group {
        return Err(ListenError::InvalidFile);
    }

    // TODO: check that all instances where we use &PIN are valid
    let group_keys = secrets::get_group_keys_from_pin(ctx, group, &PIN).unwrap();
    if crypto::verify_signature(file, &group_keys.pk_sign.0).is_err() {
        return Err(ListenError::InvalidFile);
    }

    let content_length = ctx.fat.get().unwrap().entries[slot].length as usize;

    // we will create M1 = Enc_T1(Enc_pk_trans(file) || PKM) || SM
    // create a payload buffer of the maximum size
    let mut payload = [0; size_of::<File>()
        + size_of::<crypto::PubKeyMetadata>()
        + size_of::<crypto::SymmetricMetadata>()];

    let mut payload_end = content_length;
    {
        let file_size: usize = file::FILE_METADATA_SIZE + content_length;

        let (file, rest) = payload.split_at_mut(file_size);
        let (pkm_bytes, _) = rest.split_at_mut(size_of::<crypto::PubKeyMetadata>());
        let pkm: &mut crypto::PubKeyMetadata = bytemuck::from_bytes_mut(pkm_bytes);

        // copy the file to payload
        file.copy_from_slice(&bytemuck::bytes_of(ctx.files[slot].get().unwrap())[..file_size]);

        // encrypt and write G^n, nonce, tag to PKM after the file
        let group_keys = secrets::get_group_keys_from_pin(ctx, group, &PIN).unwrap();
        let pk_transfer = group_keys.pk_trans.0;
        let _ = crypto::encrypt_payload_pub(
            file,
            &mut pkm.gn,
            &mut pkm.nonce,
            &mut pkm.tag,
            &pk_transfer,
        )
        .unwrap();

        payload_end += size_of::<crypto::PubKeyMetadata>();
    }

    // encrypt again with T1
    let (content, rest) = payload.split_at_mut(payload_end);
    let (sm_bytes, _) = rest.split_at_mut(size_of::<crypto::SymmetricMetadata>());
    let sm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(sm_bytes);

    // encrypt the content and write nonce, tag to SM
    let t1 = TRANSFER_RECV.0;
    let _ = crypto::encrypt_payload_symmetric(
        content,
        &mut sm.nonce,
        &mut sm.tag,
        &t1,
        &[Opcode::Receive.into()],
    )
    .unwrap();

    payload_end += size_of::<crypto::SymmetricMetadata>();

    Message::write(Opcode::Receive, MessagePort::UART1, &payload[..payload_end]).unwrap();

    Ok(())
}
