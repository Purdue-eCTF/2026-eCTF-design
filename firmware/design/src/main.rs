#![no_std]
#![no_main]
#![feature(breakpoint)]

mod crypto;
mod file;
mod listen;
mod message;
mod protocol;
mod secrets;
mod secrets_generated;
mod util;

use bytemuck::{Pod, Zeroable};
use core::panic::PanicInfo;
use cortex_m_rt::entry;
use mspm0l222x_hal::Peripherals;
use util::*;

use crate::{
    crypto::{
        PubKeyMetadata, SymmetricMetadata, decrypt_payload_pub, decrypt_payload_symmetric,
        encrypt_payload_pub, encrypt_payload_symmetric, sign_file, verify_signature,
    },
    file::{FatEntry, FatTable, File, FileMeta, FileName, UUID},
    message::{MAX_BODY_SIZE, Message, MessagePort, Opcode},
    secrets_generated::{GROUP_KEYS, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV},
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

#[entry]
fn main() -> ! {
    let mut ctx = Context::new(Peripherals::take().unwrap());
    for file in &ctx.files {
        // TODO: gracefully handle this failure
        assert!(file.as_ref().state == File::EMPTY || file.as_ref().state == File::FULL);
    }

    let mut message_body = [0u8; MAX_BODY_SIZE];
    loop {
        let msg_info = Message::read(MessagePort::UART0, &mut message_body).unwrap();
        let msg = &message_body[..msg_info.length as usize];

        println!("Got message {msg_info:?}");

        sensitive!(ctx, {
            match msg_info.opcode {
                Opcode::List => handle_list(&mut ctx),
                Opcode::Read => handle_read(&mut ctx, msg),
                Opcode::Write => handle_write(&mut ctx, msg),
                Opcode::Receive => handle_receive(&mut ctx, msg),
                Opcode::Interrogate => handle_interrogate(&mut ctx, msg),
                Opcode::Listen => handle_listen(&mut ctx),
                Opcode::Ack => panic!("Ack without sent message"),
                e @ (Opcode::Error | Opcode::Debug) => panic!("{e:?} should not be sent to board"),
            }
        });
    }
}

/// List files; requires pin on usage. Sends back a head with total number of
/// files and length of the message body, and then the data, with the name,
/// group, and slot of the file.
fn handle_list(ctx: &mut Context) {
    // 4 bytes at start for total number of files; file slot, name of file, group id, for 8 files
    const METADATA_SIZE: usize = core::mem::size_of::<FileMeta>();
    let mut body = [0u8; 4 + 8 * METADATA_SIZE];
    let file_list = &mut body[4..];
    let list_entries: &mut [FileMeta; 8] = bytemuck::from_bytes_mut(file_list);
    let mut counter: usize = 0;
    for i in 0..8 {
        let file = ctx.files[i].as_ref();

        // if not in use, continue
        if !file.is_full() {
            continue;
        }

        // verify file signature before handling
        // TODO: linear scan for key
        let key = GROUP_KEYS[file.protected.group as usize].pk_sign.0;
        if verify_signature(file, &key).is_err() {
            continue;
        }

        let metadata = FileMeta {
            name: file.protected.name,
            group: file.protected.group,
            slot: i as u8,
        };
        list_entries[counter] = metadata;

        counter += 1;
    }
    // set number of files listed
    body[0..4].copy_from_slice(&(counter as u32).to_le_bytes());

    // return data without the extra space allocated in the body buffer
    let actual_body = &body[..4 + counter * METADATA_SIZE];
    Message::write_header(Opcode::List, actual_body.len() as u16, MessagePort::UART0);
    Message::write(actual_body, Opcode::List, MessagePort::UART0).unwrap();
}

// Read file on given slot, returning to the host the file; requires pin on
// usage. Since the file is stored on flash encrypted, this function uses the
// pin to decrypt the file before returning it to the host.

fn handle_read(ctx: &mut Context, msg: &[u8]) {
    if msg.len() != 7 {
        panic!()
    }

    // retrieve pin from message (TODO is pin for sure in first six bytes of msg?)
    let mut pin = [0u8; 6];
    pin.copy_from_slice(&msg[0..6]);

    let pin = pin;
    let slot = msg[6] as usize;

    if slot > 7 {
        panic!()
    }

    let file_length = ctx.fat.as_ref().entries[slot].length as usize;
    let file = ctx.files[slot].as_ref();

    // die if there isn't a file here
    if !file.is_full() {
        panic!()
    }

    // get group key and verify file hasn't been tampered
    let group = file.protected.group;
    let group_key = secrets::get_group_keys_from_pin(group, &pin).unwrap();
    // TODO: linear scan for correct GROUP_KEYS value
    let key = GROUP_KEYS[file.protected.group as usize].pk_sign.0;
    verify_signature(file, &key).unwrap();

    // buf = N || PT
    let mut buf = [0; file::CONTENT_SIZE + file::NAME_SIZE];
    let (name, pt) = buf.split_at_mut(file::NAME_SIZE);

    name.copy_from_slice(&file.protected.name.0);
    pt[..file_length].copy_from_slice(&file.protected.contents[..file_length]);

    // decrypt the file into buffer
    decrypt_payload_pub(
        &mut pt[..file_length],
        &file.protected.gn,
        &file.protected.nonce,
        &file.protected.tag,
        &group_key.sk_read.0,
    )
    .unwrap();

    let total_length = file::NAME_SIZE + file_length;
    Message::write(&buf[..total_length], Opcode::Read, MessagePort::UART0).unwrap();
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct WriteFileHeader {
    pub pin: [u8; 6],
    pub slot: u8,
    pub gid: u16,
    pub name: FileName,
    pub uuid: UUID,
    pub length: u16,
}
/// Write a file received from host into flash. The file should be encrypted
/// and signed.
fn handle_write(ctx: &mut Context, msg: &[u8]) {
    let (header, data) = msg.split_at(core::mem::size_of::<WriteFileHeader>());
    let WriteFileHeader {
        pin,
        slot,
        gid: group,
        name,
        uuid,
        length,
    } = *bytemuck::from_bytes(header);

    // check if the data from message is larger than allocated data/content area in fat, or whether
    // the allocated data has incorrect length
    let data_len = length as usize;
    if data_len > file::CONTENT_SIZE || data_len != data.len() {
        panic!()
    }

    // TODO: check number of file slot requirements
    let slot = slot as usize;
    if slot > 7 {
        panic!()
    }

    // retrieve signing and read encryption keys with pin
    let pin = pin.try_into().unwrap();
    let group_key = secrets::get_group_keys_from_pin(group, &pin).unwrap();
    let pk_read = group_key.pk_read.0;

    // generate empty file variable
    let mut file = File::new();
    file.state = File::FULL;

    // set file metadata
    let protected = &mut file.protected;
    protected.name = name;
    protected.group = group;

    // set initial content data
    // we already verified that the data length is correct, so don't check again
    // TODO: do we need to read chunks?
    protected.contents[..data.len()].copy_from_slice(data);

    // encrypt everything
    encrypt_payload_pub(
        &mut protected.contents[..data_len],
        &mut protected.gn,
        &mut protected.nonce,
        &mut protected.tag,
        &pk_read,
    )
    .unwrap();
    sign_file(&mut file, &group_key.sk_sign.0).unwrap();

    // TODO: make sure file/fat can't be partially written
    let new_fat = FatEntry {
        uuid,
        length: data_len as u16,
        padding: ctx.fat.as_ref().entries[slot].padding, // what is this?
        addr: ctx.fat.as_ref().entries[slot].addr,
    };

    // TODO: just write the one fat entry
    unsafe {
        ctx.files[slot].set(&file).unwrap();
    }
    let current = ctx.fat.as_ref();
    // avoid in-place mutation
    let mut entries = current.entries;
    entries[slot] = new_fat;
    unsafe {
        ctx.fat.set(&FatTable { entries }).unwrap();
    }

    Message::write_header(Opcode::Write, 0, MessagePort::UART0);
}

fn handle_receive(ctx: &mut Context, msg: &[u8]) {
    if msg.len() != 8 {
        panic!()
    }

    let mut pin = [0u8; 6];
    pin.copy_from_slice(&msg[0..6]);

    let pin = pin;
    let read_slot = msg[6];
    let write_slot = msg[7];

    let group = 0u16;
    let group_key = secrets::get_group_keys_from_pin(group, &pin).unwrap();

    protocol::initiate_transfer(read_slot, group).unwrap();
    let mut buf = [0u8; protocol::TRANSFER_RECEIVE_MAX_LENGTH];
    let response = Message::read(MessagePort::UART1, &mut buf).unwrap();
    let data = &mut buf[..response.length as usize];

    let (outer, skm_bytes) = data.split_at_mut(data.len() - size_of::<SymmetricMetadata>());
    let sm: &SymmetricMetadata = bytemuck::from_bytes(skm_bytes);
    let t1 = TRANSFER_RECV.0;
    decrypt_payload_symmetric(outer, &sm.nonce, &sm.tag, &t1, &[Opcode::Receive.into()]).unwrap();

    let (inner, pkm_bytes) = outer.split_at_mut(outer.len() - size_of::<PubKeyMetadata>());
    let pkm: &PubKeyMetadata = bytemuck::from_bytes(pkm_bytes);
    decrypt_payload_pub(inner, &pkm.gn, &pkm.nonce, &pkm.tag, &group_key.pk_trans.0).unwrap();

    let file: &mut File = bytemuck::from_bytes_mut(inner);

    verify_signature(file, &group_key.pk_sign.0).unwrap();

    let file_size =
        response.length as usize - size_of::<SymmetricMetadata>() - size_of::<PubKeyMetadata>();
    let content_length = file_size - file::FILE_METADATA_SIZE;

    // May write over pkm, skm
    file.protected.contents[content_length..].fill(0);

    let new_fat = FatEntry {
        uuid: file.protected.uuid,
        length: content_length.try_into().unwrap(),
        padding: ctx.fat.as_ref().entries[write_slot as usize].padding, // what is this?
        addr: ctx.fat.as_ref().entries[write_slot as usize].addr,
    };

    // TODO: just write the one fat entry
    unsafe {
        ctx.files[write_slot as usize].set(file).unwrap();
        let current = ctx.fat.as_ref();
        let mut entries = current.entries;
        entries[write_slot as usize] = new_fat;
        ctx.fat.set(&FatTable { entries }).unwrap();
    }

    Message::write_header(Opcode::Receive, 0, MessagePort::UART0);
}

/// Interrogate an adjacent board for a list of files that the current board
/// has permissions for. Since the entire list of files is encrypted
/// symmetrically and each file's metadata encrypted asymmetrically, all this
/// will be decrypted before being sent back to host.
fn handle_interrogate(_ctx: &mut Context, msg: &[u8]) {
    // Command contains just the PIN
    if msg.len() != 6 {
        panic!()
    }
    let pin: &[u8; 6] = msg[..6].try_into().unwrap();

    // encrypt groups being sent over to other board
    let mut groups: [u16; GROUP_KEYS.len()] = [0u16; GROUP_KEYS.len()];

    let mut sm = crypto::SymmetricMetadata {
        nonce: [0; crypto::NONCE_SIZE],
        tag: [0; crypto::TAG_SIZE],
    };
    let mut group_count = 0;

    // Get groups for which the HSM has receive permission
    for group in GROUP_KEYS.iter() {
        let group_key = secrets::get_group_keys_from_pin(group.group, pin).unwrap();
        if group_key.sk_inter.0.is_empty() {
            continue;
        };
        groups[group_count] = group.group;
        group_count += 1;
    }

    let groups_size = group_count * 2;

    // encrypt the groups and write nonce, tag to sm
    let _ = encrypt_payload_symmetric(
        &mut bytemuck::bytes_of_mut(&mut groups)[..groups_size],
        &mut sm.nonce,
        &mut sm.tag,
        &INTERROGATE_SEND.0,
        &[Opcode::Interrogate as u8],
    )
    .unwrap();

    // copy the encrypted groups, nonce, and tag to another buffer
    let mut payload = [0; 2 * GROUP_KEYS.len() + size_of::<crypto::SymmetricMetadata>()];

    // actual payload may be smaller than the maximum size the buffer was defined with
    let actual_payload_size = group_count * 2 + size_of::<crypto::SymmetricMetadata>();

    // copy encrypted groups to the start
    payload[..group_count * 2].copy_from_slice(bytemuck::bytes_of(&groups));

    // copy nonce and tag to the end
    payload[group_count * 2..].copy_from_slice(bytemuck::bytes_of(&sm));

    // interrogate the other HSM and receive response
    Message::write(
        &payload[..actual_payload_size],
        Opcode::Interrogate,
        MessagePort::UART1,
    )
    .unwrap();
    let mut info_body = [0u8; MAX_BODY_SIZE];
    let info = Message::read(MessagePort::UART1, &mut info_body).unwrap();

    if info.opcode != Opcode::Interrogate {
        panic!("Incorrect Opcode for Retrieve Interrogate");
    }

    // PKM: PubKeyMetadata struct
    // SM: SymmetricMetadata struct

    // Expect info.body = Enc_I1(
    //    (EncFile1 || PKM1) ||
    //    (EncFile2 || PKM2) ||
    // ... ||
    //    (EncFileN || PKMN) ||
    //    SM
    // )
    // EncFilei = group || Enc_pk_inter(slot || name)

    //TODO, someone check if the change I made is correct
    let offset = info_body.len() - size_of::<crypto::SymmetricMetadata>();

    // data: concatenated, encrypted, InterrogateFile structs
    let (data, rest) = info_body.split_at_mut(offset);

    // sm: struct containing nonce and tag from encrypion with I1
    let sm: &mut crypto::SymmetricMetadata = bytemuck::from_bytes_mut(rest);

    let _ = decrypt_payload_symmetric(
        data,
        &sm.nonce,
        &sm.tag,
        &INTERROGATE_RECV.0,
        &[Opcode::Interrogate as u8],
    )
    .unwrap();
    // data = (EncFile1 || PKM1) ||
    //        (EncFile2 || PKM2) ||
    //        ... ||
    //        (EncFileN || PKMN)

    const ENTRY_SIZE: usize =
        size_of::<listen::InterrogateFile>() + size_of::<crypto::PubKeyMetadata>();
    let count = data.len() / ENTRY_SIZE;

    // HSM response: num files ||
    //        (slot_1 || group_1 || name_1) ||
    //        (slot_2 || group_2 || name_2) ||
    //        ... ||
    //        (slot_N || group_N || name_N)

    // allocate response buffer of the maximum size
    let mut response = [0; 4 + 8 * size_of::<listen::InterrogateFile>()];

    // split num_files off from the list and set it
    let (num_files, list) = response.split_at_mut(4);
    num_files.copy_from_slice(&(count as u32).to_le_bytes());

    for i in 0..count {
        // current offset in ctxt
        let offset = i * ENTRY_SIZE;
        let entry = &mut data[offset..offset + ENTRY_SIZE];

        // split file from pubkey metadata
        let (file_bytes, pkm_bytes) = entry.split_at_mut(size_of::<listen::InterrogateFile>());

        // convert to InterrogateFile and PKM
        let ifile: &mut listen::InterrogateFile = bytemuck::from_bytes_mut(file_bytes);
        let pkm: &crypto::PubKeyMetadata = bytemuck::from_bytes(pkm_bytes);

        let key = secrets::get_group_keys_from_pin(ifile.group, pin)
            .unwrap()
            .sk_inter
            .0;

        // decrypt the slot and filename
        let _ = decrypt_payload_pub(
            bytemuck::bytes_of_mut(&mut ifile.protected),
            &pkm.gn,
            &pkm.nonce,
            &pkm.tag,
            &key,
        )
        .unwrap();

        // copy to the correct offset in list
        let list_offset = i * size_of::<listen::InterrogateFile>();
        let list_entry = &mut list[list_offset..list_offset + size_of::<listen::InterrogateFile>()];
        list_entry[0] = ifile.protected.slot;
        list_entry[1..3].copy_from_slice(&u16::to_le_bytes(ifile.group));
        list_entry[3..].copy_from_slice(&ifile.protected.name.0);
    }

    let actual_message_size = 4 + count * size_of::<listen::InterrogateFile>();
    Message::write(
        &response[..actual_message_size],
        Opcode::Interrogate,
        MessagePort::UART0,
    )
    .unwrap();
}

/// Listens for any Receive or Interrogate command from an adjacent board to
/// process before sending back the corresponding data.
fn handle_listen(ctx: &mut Context) {
    Message::write_header(Opcode::Listen, 0, MessagePort::UART0);
    let mut body = [0u8; MAX_BODY_SIZE];
    let msg = Message::read(MessagePort::UART1, &mut body).unwrap();
    listen::recv(ctx, msg.opcode, &mut body).unwrap();
}
