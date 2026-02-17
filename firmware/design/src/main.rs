#![no_std]
#![no_main]
#![feature(breakpoint)]

mod crypto;
mod listen;
mod message;
mod secrets;
mod view;
mod file;
mod util;

use ed25519_dalek::{Signature, SigningKey, Signer};
use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::{Peripherals, uart::uart1};
use util::*;

use crate::{
    crypto::encrypt_payload_pub, file::{FatEntry, FatTable, File}, message::{Message, MessagePort, Opcode}
};

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    {
        println!("panic with info: {info}");
    }

    loop {}
    // cortex_m::peripheral::SCB::sys_reset();
}

// TODO: Placeholder function until using the pin to decrypt keys is implemented
fn get_group_key(group: u16, pin: &[u8; 6]) -> Result<&'static secrets::GroupKey, ()> {
    let mut r = Err(());
    for key in secrets::GROUP_KEYS.iter() {
        if key.group == group {
            r = Ok(key);
        }
    }
    r
}

#[entry]
fn main() -> ! {
    let mut ctx = Context::new(Peripherals::take().unwrap());
    for file in &ctx.files {
        // TODO: gracefully handle this failure
        assert!(file.as_ref().state == File::EMPTY || file.as_ref().state == File::FULL);
    }

    loop {
        let msg = Message::read(MessagePort::UART0).unwrap();
        println!("Got message {msg:?}");

        sensitive!(ctx, {
            match msg.opcode {
                Opcode::List => handle_list(&mut ctx),
                Opcode::Read => handle_read(&mut ctx, &msg),
                Opcode::Write => handle_write(&mut ctx, &msg),
                Opcode::Receive => handle_receive(&mut ctx),
                Opcode::Interrogate => handle_interrogate(&mut ctx),
                Opcode::Listen => handle_listen(&mut ctx),
                Opcode::Ack => panic!("Ack without sent message"),
                e @ (Opcode::Error | Opcode::Debug) => panic!("{e:?} should not be sent to board"),
            }
        });
    }
}

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)] 
#[repr(C, packed)]
struct ListEntry {
    name: [u8; view::NAME_SIZE],
    group: u16,
    slot: u8
}

fn handle_list(ctx: &mut Context) {
    // 4 bytes at start for total number of files; file slot, name of file, group id, padding, for 8 files
    const METADATA_SIZE: usize = 1 + view::NAME_SIZE + 2 + 1;
    let mut body = [0u8; 4 + 8 * METADATA_SIZE];
    let file_list = &mut body[4..];
    let list_entries: &mut [ListEntry; 8] = bytemuck::from_bytes_mut(file_list);
    let mut counter: usize = 0;
    // index * info + newline + file slot

    // - slot, file name, group ids, newline
    for i in 0..8 {
        // name | groupid | uuid | data
        // if not in use, continue
        let file = ctx.files[i].as_ref();
        if !file.is_full() {
            continue;
        }
        let key = secrets::GROUP_KEYS[file.metadata.group as usize].pk_sign.0;
        if !file.verify_signature(&key).is_ok() {
            continue;
        }

        let metadata: ListEntry = ListEntry { name: file.metadata.name, group: file.metadata.group, slot: i as u8 };
        list_entries[counter] = metadata;

        counter += 1;
    }
    body[0..4].copy_from_slice(&(counter as u32).to_le_bytes());

    let actual_body = &body[..4 + counter * METADATA_SIZE];
    Message::write_header_helper(Opcode::List, actual_body.len() as u16, MessagePort::UART0);
    Message::send_data(Opcode::List, actual_body, MessagePort::UART0).unwrap();
    
    // (does metadata need to be formatted??)
}

// read file on given slot

fn handle_read(ctx: &mut Context, msg: &Message) {
    if msg.length != 7 {
        panic!()
    }

    let mut pin = [0u8; 6];
    pin.copy_from_slice(&msg.body[0..6]);

    let pin = pin;
    let slot = msg.body[6] as usize;

    if slot > 7 {
        panic!()
    }

    let file_length = ctx.fat.as_ref().entries[slot].length as usize;
    let file = ctx.files[slot].as_ref();

    if !file.is_full() {
        panic!()
    }

    let group = file.metadata.group;
    let group_key = get_group_key(group, &pin).unwrap();
    let key = secrets::GROUP_KEYS[group as usize].pk_sign.0;
    file.verify_signature(&key).unwrap();

    let mut buf = [0; file::CONTENT_SIZE];
    buf.copy_from_slice(&file.contents[..file_length]);

    crypto::decrypt_payload_pub(&mut buf[..file_length], &file.nonce, &file.tag, &group_key.sk_read.0, &file.gn).unwrap();

    let total_length = view::NAME_SIZE + file_length;
    let mut body = [0u8; message::CHUNK_SIZE];

    message::Message::write_header_helper(Opcode::Read, total_length.try_into().unwrap(), MessagePort::UART0);

    let eat = if total_length <= message::CHUNK_SIZE {
        file_length
    } else {
        message::CHUNK_SIZE - view::NAME_SIZE
    };

    let (initial, rest) = buf.split_at(eat);
    body[..view::NAME_SIZE].copy_from_slice(&file.metadata.name);
    body[view::NAME_SIZE..view::NAME_SIZE + eat].copy_from_slice(initial);
    message::Message::write_block(&body, MessagePort::UART0).unwrap();

    for chunk in rest.chunks(message::CHUNK_SIZE) {
        //TODO: not sure if this is possible but just in case
        let cl = chunk.len();
        if cl == 0 {
            break;
        }
        body[..cl].copy_from_slice(chunk);
        message::Message::write_block(&body[..cl], MessagePort::UART0).unwrap();
    }
}

fn handle_write(ctx: &mut Context, msg: &Message) {
    if msg.length < 59 {
        panic!()
    }

    let (pin, rest) = msg.body.split_at(6);
    let (slot, rest) = rest.split_at(1);
    let (group_id, rest) = rest.split_at(file::GID_SIZE);
    let (name, rest) = rest.split_at(file::NAME_SIZE);
    let (uuid, rest) = rest.split_at(file::UUID_SIZE);
    let (length, data) = rest.split_at(2);


    let data_len = usize::from_le_bytes(length.try_into().unwrap());
    if data_len > file::CONTENT_SIZE {
        panic!()
    }

    let slot = usize::from_le_bytes(slot.try_into().unwrap());
    let group = u16::from_le_bytes(group_id.try_into().unwrap());

    // TODO: check number of file slot requirements
    if slot > 7 {
        panic!()
    }

    let group_key = get_group_key(group, &pin.try_into().unwrap()).unwrap();
    let sk_sign = SigningKey::from_bytes(&group_key.sk_sign.0);
    let pk_read = group_key.pk_read.0;

    let mut buf: [u8; size_of::<File>()] = [0u8; size_of::<File>()];
    let file: &mut File = bytemuck::from_bytes_mut(&mut buf);
    let metadata= &mut file.metadata;
    metadata.name.copy_from_slice(name);
    metadata.group = group;
    metadata.uuid.copy_from_slice(uuid); 

    let sig: Signature = sk_sign.sign(metadata);
    file.signature = sig.to_bytes();

    let first = core::cmp::min(data_len, data.len());
    file.contents[..first].copy_from_slice(&data[..first]);
    let mut offset = first;

    while offset < data_len {
        let block = Message::read_block(MessagePort::UART0).unwrap();
        let take = core::cmp::min(data_len - offset, block.len());
        file.contents[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
    // TODO
    encrypt_payload_pub(&mut file.contents[..data_len], &mut file.gn, &mut file.nonce, &mut file.tag, &pk_read).unwrap();
    
    let new_fat = FatEntry {
        uuid: uuid.try_into().unwrap(),
        length: data_len as u16,
        padding: ctx.fat.as_ref().entries[slot].padding, // what is this?
        addr: ctx.fat.as_ref().entries[slot].addr,
    };

    // TODO: just write the one fat entry
    unsafe {
        ctx.files[slot].set(file).unwrap();
        let current = ctx.fat.as_ref();
        let mut entries = current.entries;
        entries[slot] = new_fat;
        ctx.fat.set(&FatTable { entries }).unwrap();
    }

    Message::write_header_helper(Opcode::Write, 0, MessagePort::UART0);
}

fn handle_receive(ctx: &mut Context) {
    todo!()
}

// TODO
fn handle_interrogate(ctx: &mut Context) {
    // check for right pin from host
    // - if not right pin, panic w message

    let mut groups: [u16; secrets::GROUP_KEYS.len()] = [0u16; secrets::GROUP_KEYS.len()];
    let mut nonce = [0u8; 24];
    let mut tag = [0u8; 16];
    let mut group_count = 0;
    for (i, group) in secrets::GROUP_KEYS.iter().enumerate() {
        if group.pk_inter.0.is_empty() { continue };
        groups[group_count] = group.group;
        group_count += 1;
    }

    let _ = crypto::encrypt_payload_symmetric(bytemuck::bytes_of_mut(&mut groups), &mut nonce, &mut tag,&secrets::INTERROGATE_KEYS[0].0, &[Opcode::Interrogate as u8]).unwrap();

    let mut payload = [0; crypto::NONCE_SIZE + secrets::GROUP_KEYS.len() * 2 + crypto::TAG_SIZE];
    payload[..crypto::NONCE_SIZE].copy_from_slice(&nonce);
    payload[crypto::NONCE_SIZE..crypto::NONCE_SIZE + secrets::GROUP_KEYS.len() * 2].copy_from_slice(bytemuck::bytes_of(&mut groups));
    payload[crypto::NONCE_SIZE + secrets::GROUP_KEYS.len() * 2..].copy_from_slice(&tag);

    Message::send_data(Opcode::Interrogate, &payload, MessagePort::UART1).unwrap();

    let mut info = Message::read(MessagePort::UART1).unwrap();

    if info.opcode != Opcode::Interrogate {
        panic!("Incorrect Opcode for Retrieve Interrogate");
    }

    let (nonce, rest) = info.body.split_at_mut(24);
    let (data, tag) = rest.split_at_mut(rest.len() - 16);

    let _ = crypto::decrypt_payload_symmetric(data, nonce[..24].try_into().unwrap(), tag[..16].try_into().unwrap(),  &secrets::INTERROGATE_KEYS[1].0, &[Opcode::Interrogate as u8]).unwrap();

    let count = data.len() / (size_of::<listen::InterrogateFile>() + crypto::METADATA_SIZE_PUB);
    let mut list = [0; 8 * size_of::<listen::InterrogateFile>()];
    let ctxt_size = size_of::<listen::InterrogateFile>() + crypto::METADATA_SIZE_PUB;
    for i in 0..count {
        let ctxt_offset: usize = i * ctxt_size;
        let ptxt = crypto::decrypt_payload_pub_combined(&mut data[ctxt_offset..ctxt_offset + ctxt_size], &secrets::GROUP_KEYS[0].pk_inter.0).unwrap();
        
        let file_data: &[u8; size_of::<listen::InterrogateFile>()] = ptxt[..size_of::<listen::InterrogateFile>()].try_into().unwrap();
        let list_offset = i * size_of::<listen::InterrogateFile>();
        list[list_offset..list_offset + size_of::<listen::InterrogateFile>()].copy_from_slice(file_data);
    }
    Message::send_data(Opcode::Interrogate, &list, MessagePort::UART0).unwrap();

    // send interrogate request alongside permissions
    // - (group id 1, group id 2 ... associated data = interrogate)
    // wait for response
    // - response can time out (<1000ms?)
    // receive response
    // read response
    // - check if header is for interrogate
    // - on failure (if somehow), panic w message
    // - on success:
    //   - decrypt data (I1)
    //   - un-concatenate data
    //   - verify that all files are associated with the right perms
    //   - print to host failure, no files, or the files
}

fn handle_listen(ctx: &mut Context) {
    Message::write_header_helper(Opcode::Listen, 0, MessagePort::UART0);

    let mut msg = Message::read(MessagePort::UART1).unwrap();

    listen::recv(ctx, msg.opcode, &mut msg.body).unwrap();
}
