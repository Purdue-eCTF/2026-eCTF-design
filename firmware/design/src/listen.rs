use bytemuck::{Pod, Zeroable, bytes_of_mut};
use ed25519_dalek::VerifyingKey;

use crate::{Context, crypto::{self, decrypt_payload_symmetric, encrypt_payload_pub, encrypt_payload_symmetric}, message::Opcode, secrets::{GROUP_KEYS, INTERROGATE_KEYS, TRANSFER_KEYS}, view::FileView};
use mspm0l222x_hal::uart::uart1;
use thiserror::Error;


#[derive(Debug, Error)]
enum ListenError {
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Invalid slot")]
    InvalidSlot,
    #[error("Invalid group")]
    InvalidGroup,
    #[error("Invalid opcode")]
    InvalidOpcode,
}
#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct InterrogateFile {
    pub slot: u8,
    pub group: u16,
    pub name: [u8; 32]
}

pub fn recv(ctx: &mut Context, opcode: Opcode, body: &mut [u8]) -> Result<(), ListenError> {
    match opcode {
        Opcode::Interrogate => handle_interrogate(ctx, body),
        Opcode::Receive => handle_transfer(ctx, body).unwrap(),
        _ => return Err(ListenError::InvalidOpcode),
    };
    Ok(())
}

fn handle_interrogate(ctx: &mut Context, body: &mut [u8]) {
    // TODO: i0
    let i0 = INTERROGATE_KEYS[0].0;

    let opcode = [Opcode::Interrogate.into()];
    let (nonce, rest) = body.split_at_mut(crypto::NONCE_SIZE);
    let (pt, tag) = rest.split_at_mut(rest.len() - crypto::TAG_SIZE);
    let msg = decrypt_payload_symmetric(pt, nonce.try_into().unwrap(), tag.try_into().unwrap(), &i0, &opcode).unwrap();

    let mut body = [0u8; 8 * (size_of::<InterrogateFile>() + crypto::METADATA_SIZE_PUB)];
    let mut count = 0;
    for chunk in msg.chunks_exact(2) {
        let bytes: &[u8; 2] = chunk.try_into().unwrap();
        let group = u16::from_le_bytes(*bytes);

        for i in 0..8 {
            let data_len = ctx.fat.as_ref().entries[i].length as usize;
            let file = ctx.files[i].as_ref();
            let metadata = &file.metadata;
            if file.is_full() && metadata.group == group {
                let offset = count * (size_of::<InterrogateFile>() + crypto::METADATA_SIZE_PUB);
                let payload = &mut body[offset..offset + size_of::<InterrogateFile>() + crypto::METADATA_SIZE_PUB];
                let (gn, rest) = payload.split_at_mut(crypto::GN_SIZE);
                let (nonce, rest) = rest.split_at_mut(crypto::NONCE_SIZE);
                let (content, tag) = rest.split_at_mut(crypto::TAG_SIZE);
                content.copy_from_slice(bytemuck::bytes_of(&InterrogateFile { name: metadata.name, group: metadata.group, slot: i as u8 }));
                // surely
                let pk_inter = GROUP_KEYS[group as usize].pk_inter.0;
                let _ = encrypt_payload_pub(content, gn.try_into().unwrap(), nonce.try_into().unwrap(), tag.try_into().unwrap(), &pk_inter).unwrap();
                count += 1;
            }
        }
    }

    // TODO: i1
    let i1 = INTERROGATE_KEYS[1].0;
    
    let res = encrypt_payload_symmetric(bytes_of_mut(&mut body), &i1, &opcode).unwrap();
    
    let uart = uart1();
    let length: [u8; 2] = (count as u16).to_le_bytes();
    uart.write_bytes(&length[..]);
    uart.write_bytes(res);
}

fn handle_transfer<'a>(ctx: &mut Context, body: &'a mut [u8]) -> Result<(), ListenError> {
    let t0 = TRANSFER_KEYS[0].0;
    let opcode = [ListenOpcode::Receive.into()];
    let msg = decrypt_payload_symmetric(body, &t0, &opcode).unwrap();

    if msg.len() != 3 {
        return Err(ListenError::InvalidMessageLength);
    }

    let slot: usize = msg[0] as usize;
    let group = u16::from_le_bytes(msg[1..3].try_into().unwrap());

    // TODO: check slot requirements
    if slot > 7 {
        return Err(ListenError::InvalidSlot);
    }

    let data_len = ctx.fat.as_ref().entries[slot].length as usize;

    let file = ctx.files[slot].as_ref();
    if !file.is_full() || file.metadata.group != group {
        return Err(ListenError::InvalidGroup);
    }

    // should we check signature here?

    let mut buf = [0; 8192];

    buf.copy_from_slice(&ctx.files[slot].as_ref().contents);

    // surely
    let pk_transfer = GROUP_KEYS[group as usize].pk_trans.0;
    encrypt_payload_pub(&mut buf, &pk_transfer).unwrap();

    let t1 = TRANSFER_KEYS[1].0;

    let res = encrypt_payload_symmetric(&mut buf, &t1, &opcode).unwrap();
    let uart = uart1();

    let length: [u8; 2] = (res.len() as u16).to_le_bytes();
    uart.write_bytes(&length[..]);
    uart.write_bytes(res);

    Ok(())
}
