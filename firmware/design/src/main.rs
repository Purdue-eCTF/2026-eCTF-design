#![no_std]
#![no_main]
#![feature(breakpoint)]

mod crypto;
mod listen;
mod message;
mod protocol;
mod secrets;
mod file;
mod util;

use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::Peripherals;
use util::*;

use crate::{
    crypto::encrypt_payload_pub, file::{FatEntry, FatTable, File}, message::{Message, MessagePort, Opcode}
};

const METADATA_SIZE: usize = 1 + file::NAME_SIZE + 2 + 1;

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    {
        println!("panic with info: {info}");
    }

    loop {}
    // cortex_m::peripheral::SCB::sys_reset();
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
                Opcode::Receive => handle_receive(&mut ctx, &msg),
                Opcode::Interrogate => handle_interrogate(&mut ctx, &msg),
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
    name: [u8; file::NAME_SIZE],
    group: u16,
    slot: u8
}

/// List files; requires pin on usage. Sends back a head with total number of
/// files and length of the message body, and then the data, with the name,
/// group, and slot of the file.
fn handle_list(ctx: &mut Context) {
    // 4 bytes at start for total number of files; file slot, name of file, group id, for 8 files
    let mut body = [0u8; 4 + 8 * METADATA_SIZE];
    let file_list = &mut body[4..];
    let list_entries: &mut [ListEntry; 8] = bytemuck::from_bytes_mut(file_list);
    let mut counter: usize = 0;
    for i in 0..8 {
        let file = ctx.files[i].as_ref();

        // if not in use, continue
        if !file.is_full() { continue; }

        // verify file signature before handling
        let key = secrets::GROUP_KEYS[file.metadata.group as usize].pk_sign.0;
        if !crypto::verify_signature(file, &key).is_ok() {
            continue;
        }

        let metadata: ListEntry = ListEntry { name: file.metadata.name, group: file.metadata.group, slot: i as u8 };
        list_entries[counter] = metadata;

        counter += 1;
    }
    // set number of files listed
    body[0..4].copy_from_slice(&(counter as u32).to_le_bytes());

    let actual_body = &body[..4 + counter * METADATA_SIZE];
    Message::write_header_helper(Opcode::List, actual_body.len() as u16, MessagePort::UART0);
    Message::send_data(Opcode::List, actual_body, MessagePort::UART0).unwrap();
    
    // (does metadata need to be formatted??)
}

/// Read file on given slot, returning to the host the file; requires pin on
/// usage. Since the file is stored on flash encrypted, this function uses the
/// pin to decrypt the file before returning it to the host.
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

    // get group key and verify file hasn't been tampered
    let group = file.metadata.group;
    let group_key = secrets::get_group_keys_from_pin(group, &pin).unwrap();
    let key = secrets::GROUP_KEYS[file.metadata.group as usize].pk_sign.0;
    crypto::verify_signature(file, &key).unwrap();

    let mut buf = [0; file::CONTENT_SIZE];
    buf[..file_length].copy_from_slice(&file.contents[..file_length]);

    // decrypt the file
    crypto::decrypt_payload_pub(&mut buf[..file_length], &file.gn, &file.nonce, &file.tag, &group_key.sk_read.0).unwrap();

    let total_length = file::NAME_SIZE + file_length;
    let mut body = [0u8; message::CHUNK_SIZE];

    // write header back to host
    message::Message::write_header_helper(Opcode::Read, total_length.try_into().unwrap(), MessagePort::UART0);

    // write body back in chunks (esp if too big for uart)
    let eat = if total_length <= message::CHUNK_SIZE {
        file_length
    } else {
        message::CHUNK_SIZE - file::NAME_SIZE
    };

    let (initial, rest) = buf.split_at(eat);
    body[..file::NAME_SIZE].copy_from_slice(&file.metadata.name);
    body[file::NAME_SIZE..file::NAME_SIZE + eat].copy_from_slice(initial);
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

/// Write a file received from host into flash. The file should be encrypted
/// and signed.
fn handle_write(ctx: &mut Context, msg: &Message) {
    if msg.length < 59 {
        panic!()
    }

    let (pin_bytes, rest) = msg.body.split_at(6);
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

    let pin = pin_bytes.try_into().unwrap();
    let group_key = secrets::get_group_keys_from_pin(group, &pin).unwrap();
    let pk_read = group_key.pk_read.0;

    let mut buf: [u8; size_of::<File>()] = [0u8; size_of::<File>()];
    let file: &mut File = bytemuck::from_bytes_mut(&mut buf);
    let metadata= &mut file.metadata;
    metadata.name.copy_from_slice(name);
    metadata.group = group;
    metadata.uuid.copy_from_slice(uuid); 

    crypto::sign_file(file, &group_key.sk_sign.0).unwrap();

    let first = core::cmp::min(data_len, data.len());
    file.contents[..first].copy_from_slice(&data[..first]);
    let mut offset = first;

    while offset < data_len {
        let block = Message::read_block(MessagePort::UART0).unwrap();
        let take = core::cmp::min(data_len - offset, block.len());
        file.contents[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
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

fn handle_receive(_ctx: &mut Context, msg: &Message) {
    if msg.length != 8 {
        panic!()
    }

    let mut pin = [0u8; 6];
    pin.copy_from_slice(&msg.body[0..6]);

    let pin = pin;
    let read_slot = msg.body[6];
    let write_slot = msg.body[7];

    let group = 0u16;
    let group_keys = secrets::get_group_keys_from_pin(group, &pin).unwrap();

    protocol::initiate_transfer(read_slot, group).unwrap();

    todo!()
}

/// Interrogate an adjacent board for a list of files that the current board
/// has permissions for. Since the entire list of files is encrypted
/// symmetrically and each file's metadata encrypted asymmetrically, all this
/// will be decrypted before being sent back to host.
fn handle_interrogate(_ctx: &mut Context, msg: &Message) {
    // check for right pin from host
    // - if not right pin, panic w message

    if msg.length != 6 {
        panic!()
    }
    let pin: &[u8; 6] = msg.body[..6].try_into().unwrap();

    // encrypt groups being sent over to other board
    let mut groups: [u16; secrets::GROUP_KEYS.len()] = [0u16; secrets::GROUP_KEYS.len()];

    let mut sm = crypto::SymmetricMetadata { nonce: [0; crypto::NONCE_SIZE], tag: [0; crypto::TAG_SIZE] };
    let mut group_count = 0;
    for group in secrets::GROUP_KEYS.iter() {
        if group.pk_inter.0.is_empty() { continue };
        groups[group_count] = group.group;
        group_count += 1;
    }

    let _ = crypto::encrypt_payload_symmetric(bytemuck::bytes_of_mut(&mut groups), &mut sm.nonce, &mut sm.tag,&secrets::INTERROGATE_KEYS[0].0, &[Opcode::Interrogate as u8]).unwrap();

    let mut payload = [0; 2 * secrets::GROUP_KEYS.len() + size_of::<crypto::SymmetricMetadata>()];
    let actual_payload_size = group_count * 2 + size_of::<crypto::SymmetricMetadata>();
    payload[..group_count * 2].copy_from_slice(bytemuck::bytes_of(&groups));
    payload[group_count * 2..].copy_from_slice(bytemuck::bytes_of(&sm));
    Message::send_data(Opcode::Interrogate, &payload[..actual_payload_size], MessagePort::UART1).unwrap();

    let mut info = Message::read(MessagePort::UART1).unwrap();

    if info.opcode != Opcode::Interrogate {
        panic!("Incorrect Opcode for Retrieve Interrogate");
    }

    let offset = info.body.len() - size_of::<crypto::SymmetricMetadata>();
    let (data, rest) = info.body.split_at_mut(offset);
    let sm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(rest);

    let _ = crypto::decrypt_payload_symmetric(data, &sm.nonce, &sm.tag,  &secrets::INTERROGATE_KEYS[1].0, &[Opcode::Interrogate as u8]).unwrap();

    const ENTRY_SIZE: usize = size_of::<listen::InterrogateFile>() + size_of::<crypto::PubKeyMetadata>();
    let count = data.len() / ENTRY_SIZE;

    let mut response = [0; 4 + 8 * size_of::<listen::InterrogateFile>()];
    let (num_files, rest) = response.split_at_mut(4);
    num_files.copy_from_slice(&(count as u32).to_le_bytes());

    let mut list: [u8; 8 * size_of::<listen::InterrogateFile>()] = rest.try_into().unwrap();
    for i in 0..count {
        let offset = i * ENTRY_SIZE;
        let entry = &mut data[offset..offset + ENTRY_SIZE];
        let (file_bytes, rest) = entry.split_at_mut(size_of::<listen::InterrogateFile>());

        let ifile: &mut listen::InterrogateFile = bytemuck::from_bytes_mut(file_bytes);

        let pkm: &crypto::PubKeyMetadata = bytemuck::from_bytes(rest);
        let key = secrets::get_group_keys_from_pin(ifile.group, pin).unwrap().sk_inter.0;
        let _ = crypto::decrypt_payload_pub(bytemuck::bytes_of_mut(&mut ifile.protected), &pkm.gn, &pkm.nonce, &pkm.tag, &key).unwrap();
        let list_offset = i * size_of::<listen::InterrogateFile>();
        let list_entry = &mut list[list_offset..list_offset + size_of::<listen::InterrogateFile>()];
        list_entry[0] = ifile.protected.slot;
        list_entry[1..3].copy_from_slice(&u16::to_le_bytes(ifile.group));
        list_entry[3..].copy_from_slice(&ifile.protected.name);
    }

    let actual_message_size = 4 + count * size_of::<listen::InterrogateFile>();
    Message::send_data(Opcode::Interrogate, &response[..actual_message_size], MessagePort::UART0).unwrap();

}

/// Listens for any Receive or Interrogate command from an adjacent board to
/// process before sending back the corresponding data.
fn handle_listen(ctx: &mut Context) {
    Message::write_header_helper(Opcode::Listen, 0, MessagePort::UART0);
    let mut msg = Message::read(MessagePort::UART1).unwrap();
    listen::recv(ctx, msg.opcode, &mut msg.body).unwrap();
}
