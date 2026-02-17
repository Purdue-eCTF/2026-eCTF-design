use bytemuck::{Pod, Zeroable};

use crate::{
    Context, crypto, file::File, message::{Message, MessagePort, Opcode}, secrets::{INTERROGATE_KEYS, TRANSFER_KEYS, get_group_keys}
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
    let i0 = INTERROGATE_KEYS[0].0;

    let (ct, rest) = body.split_at_mut(body.len() - size_of::<crypto::SymmetricMetadata>());
    let sm_recv: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(rest);
    let msg = crypto::decrypt_payload_symmetric(ct, &sm_recv.nonce, &sm_recv.tag, &i0, &[Opcode::Interrogate.into()]).unwrap();


    const ENTRY_SIZE: usize = size_of::<InterrogateFile>() + size_of::<crypto::PubKeyMetadata>();
    let mut payload = [0; 8 * ENTRY_SIZE + size_of::<crypto::SymmetricMetadata>()];
    let (body, rest) = payload.split_at_mut(8 * ENTRY_SIZE);
    let sm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(rest);
    let mut count = 0;
    for chunk in msg.chunks_exact(2) {
        let bytes: &[u8; 2] = chunk.try_into().unwrap();
        let group = u16::from_le_bytes(*bytes);

        for i in 0..8 {
            let file = ctx.files[i].as_ref();
            let metadata = &file.metadata;
            if file.is_full() && metadata.group == group {
                let entry = &mut body[count * ENTRY_SIZE..(count + 1) * ENTRY_SIZE];
                let (content, pkm) = entry.split_at_mut(size_of::<InterrogateFile>());
                let ifile: &mut InterrogateFile = bytemuck::from_bytes_mut(content);
                *ifile = InterrogateFile {
                    group: metadata.group,
                    protected: InterrogateFileProtected {
                        slot: i as u8,
                        name: metadata.name,
                    },
                };
                let pkm: &mut crypto::PubKeyMetadata = bytemuck::from_bytes_mut(pkm);
                let key = get_group_keys(group).unwrap().pk_inter.0;
                let _ = crypto::encrypt_payload_pub(bytemuck::bytes_of_mut(&mut ifile.protected), &mut pkm.gn, &mut pkm.nonce, &mut pkm.tag, &key).unwrap();
                count += 1;
            }
        }
    }

    let i1 = INTERROGATE_KEYS[1].0;
    
    let body_size = count * ENTRY_SIZE;
    let _ = crypto::encrypt_payload_symmetric(&mut body[..body_size],  &mut sm.nonce, &mut sm.tag, &i1, &[Opcode::Interrogate.into()]).unwrap();
    
    let payload_size = body_size + size_of::<crypto::SymmetricMetadata>();
    Message::send_data(Opcode::Interrogate, &body[..payload_size], MessagePort::UART1).unwrap();
}

fn handle_transfer<'a>(ctx: &mut Context, body: &'a mut [u8]) -> Result<(), ListenError> {
    let t0 = TRANSFER_KEYS[0].0;

    let (ct, rest) =  body.split_at_mut(body.len() - size_of::<crypto::SymmetricMetadata>());
    let sm_recv: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(rest);
    let msg = crypto::decrypt_payload_symmetric(ct, &sm_recv.nonce, &sm_recv.tag, &t0, &[Opcode::Receive.into()]).unwrap();

    if msg.len() != 3 {
        return Err(ListenError::InvalidMessageLength);
    }

    let slot: usize = msg[0] as usize;
    let group = u16::from_le_bytes(msg[1..3].try_into().unwrap());

    if slot > 7 {
        return Err(ListenError::InvalidFile);
    }

    let file = ctx.files[slot].as_ref();
    if !file.is_full() || file.metadata.group != group {
        return Err(ListenError::InvalidFile);
    }

    let pk_sign = get_group_keys(group).unwrap().pk_sign.0;
    if !crypto::verify_signature(&file, &pk_sign).is_ok() {
        return Err(ListenError::InvalidFile);
    }

    let file_size = ctx.fat.as_ref().entries[slot].length as usize;
    let mut payload = [0; size_of::<File>() + size_of::<crypto::PubKeyMetadata>() + size_of::<crypto::SymmetricMetadata>()];

    let mut payload_end = file_size;
    {
        let (file, rest) = payload.split_at_mut(file_size);
        let (pkm_bytes, _) = rest.split_at_mut(size_of::<crypto::PubKeyMetadata>());
        let pkm: &mut crypto::PubKeyMetadata = bytemuck::from_bytes_mut(pkm_bytes);

        file.copy_from_slice(&bytemuck::bytes_of(ctx.files[slot].as_ref())[..file_size]);
        let pk_transfer = get_group_keys(group).unwrap().pk_trans.0;
        let _ = crypto::encrypt_payload_pub(file, &mut pkm.gn, &mut pkm.nonce, &mut pkm.tag, &pk_transfer).unwrap();

        payload_end += size_of::<crypto::PubKeyMetadata>();
    }

    let (content, rest) = payload.split_at_mut(payload_end);
    let (sm_bytes, _) = rest.split_at_mut(size_of::<crypto::SymmetricMetadata>());
    let sm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(sm_bytes);

    let t1 = TRANSFER_KEYS[1].0;
    let _ = crypto::encrypt_payload_symmetric(content, &mut sm.nonce, &mut sm.tag, &t1, &[Opcode::Receive.into()]).unwrap();

    payload_end += size_of::<crypto::SymmetricMetadata>();
    Message::send_data(Opcode::Receive, &payload[..payload_end], MessagePort::UART1).unwrap();

    Ok(())
}
