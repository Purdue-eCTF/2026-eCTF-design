use bytemuck::{Pod, Zeroable, bytes_of_mut};

use crate::{Context, crypto::{decrypt_payload_symmetric, encrypt_payload_pub, encrypt_payload_symmetric}, view::FileView};
use mspm0l222x_hal::uart::uart;
use thiserror::Error;


#[derive(Debug, Error)]
enum ListenError {
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Invalid slot")]
    InvalidSlot,
    #[error("Invalid group")]
    InvalidGroup,
}

pub(crate) enum ListenOpcode {
    Interrogate,
    Receive
}
impl TryFrom<u8> for ListenOpcode {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            b'I' => Ok(Self::Interrogate),
            b'C' => Ok(Self::Receive),
            _ => Err(()),
        }
    }
}

impl From<ListenOpcode> for u8 {
    fn from(opcode: ListenOpcode) -> u8 {
        match opcode {
            ListenOpcode::Interrogate => b'I',
            ListenOpcode::Receive => b'C'
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct InterrogateFile {
    name : [u8; 32],
    group: u16,
    slot: u8,
    _pad: u8,
}


pub fn recv(ctx: &mut Context, opcode: ListenOpcode, body: &mut [u8]) {
    match opcode {
        ListenOpcode::Interrogate => handle_interrogate(ctx, body),
        ListenOpcode::Receive => handle_transfer(ctx, body).unwrap()
    };
}

fn handle_interrogate(ctx: &mut Context, body: &mut [u8]) {
    // TODO: i0
    let i0: [u8; 32] = [0; 32];

    let opcode = [ListenOpcode::Interrogate.into()];
    let msg = decrypt_payload_symmetric(body, &i0, &opcode).unwrap();

    let mut body = [const { InterrogateFile { name: [0; 32], group: 0, slot: 0, _pad: 0 } }; 8];
    let mut count = 0;
    for chunk in msg.chunks_exact(2) {
        let bytes: &[u8; 2] = chunk.try_into().unwrap();
        let group = u16::from_le_bytes(*bytes);

        for i in 0..8 {
            let data_len = ctx.fat[i].length as usize;
            let file = FileView::from_file(&ctx.files[i].contents, data_len);
            if file.exists && file.group == group {
                body[count] = InterrogateFile { name: *file.name, group: file.group, slot: i as u8, _pad: 0 };

                // TODO: get_pk_inter(group)
                let pk_inter = get_pk_inter(group);
                let _ = encrypt_payload_pub(bytes_of_mut(&mut body[count]), &pk_inter).unwrap();
                count += 1;
            }
        }
    }

    // TODO: i1
    let i1: [u8; 32] = [0; 32];
    
    let res = encrypt_payload_symmetric(bytes_of_mut(&mut body), &i1, &opcode).unwrap();
    
    // TODO: uart1
    let uart = uart();
    let length: [u8; 2] = (count as u16).to_le_bytes();
    uart.write_bytes(&length[..]);
    uart.write_bytes(res);
}

fn handle_transfer<'a>(ctx: &mut Context, body: &'a mut [u8]) -> Result<(), ListenError> {
    let t0 = [0; 32];
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

    let data_len = ctx.fat[slot].length as usize;

    let file = FileView::from_file(&ctx.files[slot].contents, data_len);
    if !file.exists || file.group != group {
        return Err(ListenError::InvalidGroup);
    }

    // should we check signature here?

    let mut buf = [0; 8191];

    buf.copy_from_slice(&ctx.files[slot].contents[..8191]);

    // TODO: get pk_transfer
    let pk_transfer = get_pk_transfer(file.group);
    encrypt_payload_pub(&mut buf, &pk_transfer).unwrap();

    // TODO: t1
    let t1 = [0; 32];

    let res = encrypt_payload_symmetric(&mut buf, &t1, &opcode).unwrap();
    let uart = uart();

    let length: [u8; 2] = (res.len() as u16).to_le_bytes();
    uart.write_bytes(&length[..]);
    uart.write_bytes(res);

    Ok(())
}

fn get_pk_inter(group: u16) -> [u8; 32] {
    // TODO: get_pk_inter(group)
    let pk_inter = [0; 32];
    pk_inter
}

fn get_pk_transfer(group: u16) -> [u8; 32] {
    // TODO: get_pk_transfer(group)
    let pk_transfer = [0; 32];
    pk_transfer
}