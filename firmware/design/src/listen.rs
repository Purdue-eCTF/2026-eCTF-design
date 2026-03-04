use bytemuck::Zeroable;
use design_macros::rand_ops;
use mspm0l222x_hal::trng;

use crate::{
    context::Context,
    crypto::{PubKeyMetadata, SymmetricMetadata},
    message::{Message, MessagePort, MessageUart, Opcode},
    protocol::{
        EncryptedInterrogateRequest, EncryptedInterrogateResponse, EncryptedTransferRequest,
        EncryptedTransferResponseBody, EncryptedTransferResponseHeader, GroupId,
        InterrogateFileInfo, InterrogateFileProtected, ProtocolError, SafeError, SymEncryptable,
        TransferResponseHeader,
    },
    secrets::{self, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV, TRANSFER_SEND},
};

/// Handle a command received in listen mode.
pub fn recv(ctx: &mut Context, opcode: Opcode, body: &mut [u8]) -> Result<(), ProtocolError> {
    match opcode {
        Opcode::Interrogate => respond_interrogate(ctx, body)?,
        Opcode::Receive => respond_transfer(ctx, body)?,
        _ => return Err(SafeError::InvalidOpcode.into()),
    };
    Ok(())
}

/// Handle an interrogate command from a neighbor HSM, received while in listen mode.
#[inline(never)]
fn respond_interrogate(ctx: &mut Context, body: &mut [u8]) -> Result<(), ProtocolError> {
    if body.len() != size_of::<EncryptedInterrogateRequest>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let request: &mut EncryptedInterrogateRequest = bytemuck::from_bytes_mut(body);
    request.decrypt(&INTERROGATE_SEND)?;

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
                let Some(ifile) = response.protected.files.get_mut(count) else {
                    return Err(ProtocolError::InvalidMessageLength);
                };
                *ifile = InterrogateFileInfo {
                    protected: InterrogateFileProtected {
                        slot: i as u8,
                        name: metadata.name,
                    },
                    group_id: GroupId::new(metadata.group),
                    metadata: SymmetricMetadata::empty(),
                };
                ifile.encrypt(&group_keys.k_inter)?;

                count += 1;
            }
        }
    }

    response.protected.file_count = count as u8;
    response.encrypt(&INTERROGATE_RECV)?;

    Message::write(
        Opcode::Interrogate,
        MessagePort::UART1,
        bytemuck::bytes_of(&response),
    )?;

    Ok(())
}

/// Handle a receive command from a neighbor HSM, received while in listen mode.
#[inline(never)]
fn respond_transfer(ctx: &mut Context, body: &mut [u8]) -> Result<(), ProtocolError> {
    if body.len() != size_of::<EncryptedTransferRequest>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let request: &mut EncryptedTransferRequest = bytemuck::from_bytes_mut(body);
    request.decrypt(&TRANSFER_SEND)?;

    let slot: usize = request.protected.slot as usize;

    if slot > 7 {
        return Err(SafeError::InvalidSlot.into());
    }

    let file_src = ctx.files[slot].get().ok_or(ProtocolError::InvalidFile)?;

    let group_keys = secrets::get_enc_group_keys(file_src.protected.group)?;

    let mut response_header = EncryptedTransferResponseHeader {
        protected: TransferResponseHeader {
            group_id: GroupId::new(file_src.protected.group),
            pub_metadata: PubKeyMetadata::empty(),
        },
        metadata: SymmetricMetadata::empty(),
    };

    let mut response_body = EncryptedTransferResponseBody {
        protected: *file_src,
        metadata: SymmetricMetadata::empty(),
    };

    // perform encryptions
    response_header.protected.pub_metadata = PubKeyMetadata::encrypt(
        bytemuck::bytes_of_mut(&mut response_body.protected),
        &group_keys.pk_trans,
        &file_src.protected.group.to_le_bytes(),
    )?;

    response_header.encrypt(&TRANSFER_RECV)?;
    response_body
        .encrypt_with_associated_data(&TRANSFER_RECV, bytemuck::bytes_of(&response_header))?;

    Message::write(
        Opcode::Receive,
        MessagePort::UART1,
        bytemuck::bytes_of(&response_header),
    )?;
    Message::read_ack(MessagePort::UART1)?;

    let writer = MessageUart::new(MessagePort::UART1);
    writer.write_bytes(bytemuck::bytes_of(&response_body));
    rand_ops!(trng::trng());

    Ok(())
}
