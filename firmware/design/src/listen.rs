use bytemuck::Zeroable;

use crate::{
    context::Context,
    crypto::{PubKeyMetadata, SymmetricMetadata},
    file::File,
    message::{Message, MessagePort, Opcode},
    protocol::{
        EncryptedInterrogateRequest, EncryptedInterrogateResponse, GroupId, InterrogateFileInfo,
        InterrogateFileProtected, MAX_NUM_FILES, ProtocolError, SymEncryptable,
        TransferM0Encrypted,
    },
    secrets::{self, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV},
};

pub fn recv(ctx: &mut Context, opcode: Opcode, body: &mut [u8]) -> Result<(), ProtocolError> {
    match opcode {
        Opcode::Interrogate => respond_interrogate(ctx, body)?,
        Opcode::Receive => respond_transfer(ctx, body)?,
        _ => return Err(ProtocolError::InvalidOpcode),
    };
    Ok(())
}

#[inline(never)]
fn respond_interrogate(ctx: &mut Context, body: &mut [u8]) -> Result<(), ProtocolError> {
    if body.len() != size_of::<EncryptedInterrogateRequest>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let request: &mut EncryptedInterrogateRequest = bytemuck::from_bytes_mut(body);
    request.decrypt(&INTERROGATE_SEND.0)?;

    let request_count = request.protected.group_count as usize;
    if request_count > request.protected.groups.len() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut response = EncryptedInterrogateResponse::zeroed();
    let mut count = 0;
    for group_id in request.protected.groups[..request_count].iter() {
        let group = group_id.get();
        for i in 0..8 {
            let Some(file) = ctx.files[i].get() else {
                continue;
            };
            // check if the group id matches
            let metadata = &file.protected;
            // if a valid file matches the group, add it to the list
            if metadata.group == group {
                let group_keys = secrets::get_enc_group_keys(group)?;
                let ifile = &mut response.protected.files[count];
                *ifile = InterrogateFileInfo {
                    protected: InterrogateFileProtected {
                        slot: i as u8,
                        name: metadata.name,
                    },
                    group_id: GroupId::new(metadata.group),
                    metadata: SymmetricMetadata::empty(),
                };
                ifile.encrypt(&group_keys.k_inter.0)?;

                count += 1;
            }
        }
    }

    response.protected.file_count = count as u8;
    response.encrypt(&INTERROGATE_RECV.0)?;

    Message::write(
        Opcode::Interrogate,
        MessagePort::UART1,
        bytemuck::bytes_of(&response),
    )?;

    Ok(())
}

#[inline(never)]
fn respond_transfer(ctx: &mut Context, body: &mut [u8]) -> Result<(), ProtocolError> {
    if body.len() != size_of::<TransferM0Encrypted>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

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
