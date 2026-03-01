use bytemuck::{Pod, Zeroable};

use crate::{
    context::Context,
    crypto::{self, PubKeyMetadata, SymmetricMetadata, unwrap_symmetric_message},
    file::{File, FileName},
    message::{MAX_BODY_SIZE, Message, MessagePort, Opcode},
    protocol::{ProtocolError, TransferM0Encrypted},
    secrets::{self, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV},
};
#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct InterrogateFile {
    // group must not be u16 because it is ub to take reference to u16 in packed struct with potentially less alignment
    pub group_bytes: [u8; 2],
    pub protected: InterrogateFileProtected,
}

impl InterrogateFile {
    pub fn group(&self) -> u16 {
        u16::from_le_bytes(self.group_bytes)
    }

    pub fn set_group(&mut self, group: u16) {
        self.group_bytes = group.to_le_bytes();
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct InterrogateFileProtected {
    pub slot: u8,
    pub name: FileName,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct EncryptedInterrogateInfo {
    pub file: InterrogateFile,
    pub metadata: SymmetricMetadata,
}

impl EncryptedInterrogateInfo {
    pub fn encrypt(&mut self, key: &[u8; 32]) -> Result<(), ProtocolError> {
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
            SymmetricMetadata::encrypt(bytemuck::bytes_of_mut(protected), key, group_bytes)?;

        Ok(())
    }

    pub fn decrypt(&mut self, key: &[u8; 32]) -> Result<(), ProtocolError> {
        let Self {
            file:
                InterrogateFile {
                    group_bytes,
                    protected,
                },
            metadata,
            ..
        } = self;

        metadata.decrypt(bytemuck::bytes_of_mut(protected), key, group_bytes)?;

        Ok(())
    }
}

pub fn recv(
    ctx: &mut Context,
    opcode: Opcode,
    body: &mut [u8],
    msg_len: usize,
) -> Result<(), ProtocolError> {
    match opcode {
        Opcode::Interrogate => respond_interrogate(ctx, body, msg_len)?,
        Opcode::Receive => respond_transfer(ctx, body, msg_len)?,
        _ => return Err(ProtocolError::InvalidOpcode),
    };
    Ok(())
}

#[inline(never)]
fn respond_interrogate(
    ctx: &mut Context,
    body: &mut [u8],
    msg_len: usize,
) -> Result<(), ProtocolError> {
    if msg_len > MAX_BODY_SIZE {
        return Err(ProtocolError::InvalidMessageLength);
    }

    Message::read_body(MessagePort::UART1, &mut body[..msg_len])?;
    let body = &mut body[..msg_len];

    // Expect body = Enc_I0(Group1 || Group2 || ... || GroupN) || SM
    let i0 = INTERROGATE_SEND.0;

    let msg = unwrap_symmetric_message(body, &i0, &[Opcode::Interrogate.into()])?;

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
    const ENTRY_SIZE: usize = size_of::<InterrogateFile>() + size_of::<crypto::SymmetricMetadata>();

    // allocate a payload buffer of the maximum size and write the ciphertext into it
    let mut payload = [0; 8 * ENTRY_SIZE + size_of::<crypto::SymmetricMetadata>()];

    // list: the encrypted InterrogateFiles
    // sm_bytes: contains SM
    let (list, _) = payload.split_at_mut(8 * ENTRY_SIZE);
    let mut count = 0;
    for chunk in msg.chunks_exact(2) {
        let group = u16::from_le_bytes([chunk[0], chunk[1]]);

        for i in 0..8 {
            let file = ctx.files[i].get().ok_or(ProtocolError::InvalidFile)?;
            // check if the slot is full and the group id matches
            let metadata = &file.protected;
            // if a valid file matches the group, add it to the list
            if metadata.group == group {
                let group_keys = secrets::get_enc_group_keys(group)?;

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
                let pkm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(pkm);
                let key = group_keys.k_inter.0;

                // encrypt just the slot and filename
                // write G^n, nonce, tag to PKM at the end of entry
                // HSM1 needs to read group in order to get the correct key
                crypto::encrypt_payload_symmetric(
                    bytemuck::bytes_of_mut(&mut ifile.protected),
                    &mut pkm.nonce,
                    &mut pkm.tag,
                    &key,
                    &metadata.group.to_le_bytes(),
                )?;
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
    crypto::encrypt_payload_symmetric(
        body,
        &mut sm.nonce,
        &mut sm.tag,
        &i1,
        &[Opcode::Interrogate.into()],
    )?;

    let payload_size = body_size + size_of::<crypto::SymmetricMetadata>();
    Message::write(
        Opcode::Interrogate,
        MessagePort::UART1,
        &payload[..payload_size],
    )?;

    Ok(())
}

#[inline(never)]
fn respond_transfer(
    ctx: &mut Context,
    body: &mut [u8],
    msg_len: usize,
) -> Result<(), ProtocolError> {
    if msg_len != size_of::<TransferM0Encrypted>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let body = &mut body[..size_of::<TransferM0Encrypted>()];
    Message::read_body(MessagePort::UART1, body)?;

    let enc: &TransferM0Encrypted = bytemuck::from_bytes(body);
    let m0 = enc.decrypt()?;

    let slot: usize = m0.slot as usize;

    if slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    let file_src = ctx.files[slot].get().ok_or(ProtocolError::InvalidFile)?;

    let group_keys = secrets::get_enc_group_keys(file_src.protected.group)?;
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
    file.copy_from_slice(bytemuck::bytes_of(file_src));

    // encrypt file with pk trans
    *pub_key_meta = PubKeyMetadata::encrypt(file, &group_keys.pk_trans.0, &group_id_bytes)?;

    // write associated data
    group_id.copy_from_slice(&group_id_bytes);

    let (data, symmetric_meta) = payload.split_at_mut(payload_len - size_of::<SymmetricMetadata>());
    let symmetric_meta: &mut SymmetricMetadata = bytemuck::from_bytes_mut(symmetric_meta);

    // encrypt file with T1
    *symmetric_meta =
        SymmetricMetadata::encrypt(data, &TRANSFER_RECV.0, &[Opcode::Receive.into()])?;

    Message::write(Opcode::Receive, MessagePort::UART1, &payload)?;

    Ok(())
}
