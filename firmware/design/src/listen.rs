use bytemuck::Zeroable;

use crate::{
    context::Context,
    crypto::{PubKeyMetadata, SymmetricMetadata},
    message::{Message, MessagePort, Opcode},
    protocol::{
        EncryptedInterrogateRequest, EncryptedInterrogateResponse, EncryptedTransferRequest,
        EncryptedTransferResponse, GroupId, InterrogateFileInfo, InterrogateFileProtected,
        ProtocolError, PubEncryptable, SymEncryptable, TransferResponse,
    },
    secrets::{self, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV, TRANSFER_SEND},
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
    if body.len() != size_of::<EncryptedTransferRequest>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let request: &mut EncryptedTransferRequest = bytemuck::from_bytes_mut(body);
    request.decrypt(&TRANSFER_SEND.0)?;

    let slot: usize = request.protected.slot as usize;

    if slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    let file_src = ctx.files[slot].get().ok_or(ProtocolError::InvalidFile)?;

    let group_keys = secrets::get_enc_group_keys(file_src.protected.group)?;
    let mut response = EncryptedTransferResponse {
        protected: TransferResponse {
            file: *file_src,
            group_id: GroupId::new(file_src.protected.group),
            pub_metadata: PubKeyMetadata::empty(),
        },
        metadata: SymmetricMetadata::empty(),
    };

    response.protected.encrypt(&group_keys.pk_trans.0)?;
    response.encrypt(&TRANSFER_RECV.0)?;

    Message::write(
        Opcode::Receive,
        MessagePort::UART1,
        bytemuck::bytes_of(&response),
    )?;

    Ok(())
}
