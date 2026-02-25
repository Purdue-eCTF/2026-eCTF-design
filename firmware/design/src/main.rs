#![no_std]
#![no_main]

mod context;
mod crypto;
mod file;
mod flash;
mod listen;
mod message;
mod protocol;
mod salt;
mod secrets;

use bytemuck::{Pod, Zeroable};
use context::*;
use core::panic::PanicInfo;
use cortex_m_rt::entry;
use design_macros::rand_ops;
use mspm0l222x_hal::Peripherals;
use mspm0l222x_hal::trng;

use crate::{
    crypto::{
        SymmetricMetadata, decrypt_payload_pub, encrypt_payload_pub, sign_file, unwrap_pub_message,
        unwrap_symmetric_message, verify_signature,
    },
    file::{FatEntry, FatTable, File, FileMeta, FileName, UUID},
    listen::EncryptedInterrogateInfo,
    message::{CHUNK_SIZE, HEADER_SIZE, MAX_BODY_SIZE, Message, MessagePort, Opcode},
    protocol::ProtocolError,
    secrets::{
        COPY_PERM_GROUPS, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV, get_enc_group_keys,
    },
};

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    // #[cfg(debug_assertions)]
    {
        eprintln!("{info}");
    }

    // loop {}
    cortex_m::peripheral::SCB::sys_reset();
}

#[entry]
fn main() -> ! {
    let mut ctx = Context::new(Peripherals::take().unwrap());

    for file in &ctx.files {
        // TODO: gracefully handle this failure
        let Some(file) = file.get() else {
            panic!("file with no flash entry");
        };
        assert!(file.state == File::EMPTY || file.state == File::FULL);
    }

    loop {
        let msg_info = Message::read_header(MessagePort::UART0).unwrap();

        println!("Got message {msg_info:?}");

        let start = ctx.time();
        sensitive!(ctx, {
            // rand_ops!(trng::trng());

            let result = match msg_info.opcode {
                Opcode::List => handle_list(&mut ctx, msg_info.length as usize),
                Opcode::Read => handle_read(&mut ctx, msg_info.length as usize),
                Opcode::Write => handle_write(&mut ctx, msg_info.length as usize),
                Opcode::Receive => handle_receive(&mut ctx, msg_info.length as usize),
                Opcode::Interrogate => handle_interrogate(&mut ctx, msg_info.length as usize),
                Opcode::Listen => handle_listen_request(&mut ctx),
                Opcode::Ack => Ok(()),
                e @ (Opcode::Error | Opcode::Debug) => panic!("{e:?} should not be sent to board"),
            };

            if let Err(err) = result {
                panic!("handler failed: {err}");
            }
        });
        let elapsed = ctx.time() - start;
        // TODO: remove this before submitting
        if let Some((_, budget)) = TIME_BUDGET_MS
            .iter()
            .find(|(opcode, _)| *opcode == msg_info.opcode)
        // && elapsed > *budget
        {
            println!("Took {elapsed} ms to run, expected {budget}");
        }
    }
}

const TIME_BUDGET_MS: &[(Opcode, u32)] = &[
    (Opcode::List, 500),
    (Opcode::Read, 3000),
    (Opcode::Write, 3000),
    (Opcode::Receive, 3000),
    (Opcode::Interrogate, 1000),
];

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ListHeader {
    pub pin: [u8; 6],
}

/// List files; requires pin on usage. Sends back a head with total number of
/// files and length of the message body, and then the data, with the name,
/// group, and slot of the file.
fn handle_list(ctx: &mut Context, msg_len: usize) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ListHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ListHeader>()];
    Message::send_ack(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ListHeader { pin } = *bytemuck::from_bytes(&msg);

    let _k_auth = ctx.k_auth(&pin)?;

    // 4 bytes at start for total number of files; file slot, name of file, group id, for 8 files
    const METADATA_SIZE: usize = core::mem::size_of::<FileMeta>();
    let mut body = [0u8; 4 + 8 * METADATA_SIZE];
    let file_list = &mut body[4..];
    let list_entries: &mut [FileMeta; 8] = bytemuck::from_bytes_mut(file_list);
    let mut counter: usize = 0;
    for i in 0..8 {
        // if not in use or flash entry is empty, continue
        let Some(file) = ctx.files[i].get().filter(|f| f.is_full()) else {
            continue;
        };

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
    Message::write(Opcode::List, MessagePort::UART0, actual_body)?;
    Ok(())
}
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ReadFileHeader {
    pub pin: [u8; 6],
    pub slot: u8,
}

// Read file on given slot, returning to the host the file; requires pin on
// usage. Since the file is stored on flash encrypted, this function uses the
// pin to decrypt the file before returning it to the host.
fn handle_read(ctx: &mut Context, msg_len: usize) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ReadFileHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ReadFileHeader>()];
    Message::send_ack(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ReadFileHeader { pin, slot } = *bytemuck::from_bytes(&msg);
    let slot = slot as usize;

    if slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    let file = ctx.files[slot].get().ok_or(ProtocolError::InvalidFile)?;
    let file_length = file.protected.contents_length as usize;

    // die if there isn't a file here
    if !file.is_full() {
        return Err(ProtocolError::InvalidFile);
    }

    // get group key and verify file hasn't been tampered
    let group = file.protected.group;
    let group_key = secrets::get_group_keys_from_pin(ctx, group, &pin)?;
    let pk_sign = get_enc_group_keys(group)?.pk_sign.0;
    verify_signature(file, &pk_sign)?;

    // buf = N || PT
    let mut buf = [0; file::CONTENT_SIZE + file::NAME_SIZE];
    let (name, pt) = buf.split_at_mut(file::NAME_SIZE);

    name.copy_from_slice(&file.protected.name.0);
    pt[..file_length].copy_from_slice(&file.protected.contents.0[..file_length]);
    let ad = file.protected.associated_data();

    // decrypt the file into buffer
    let sk_read = group_key.sk_read.ok_or(ProtocolError::InvalidGroup)?;
    decrypt_payload_pub(
        &mut pt[..file_length],
        &file.protected.gn,
        &file.protected.nonce,
        &file.protected.tag,
        &sk_read.0,
        &ad,
    )?;

    let total_length = file::NAME_SIZE + file_length;
    Message::write(Opcode::Read, MessagePort::UART0, &buf[..total_length])?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct WriteFileHeader {
    pub pin: [u8; 6],
    pub slot: u8,
    pub group: u16,
    pub name: FileName,
    pub uuid: UUID,
    pub length: u16,
}

/// Write a file received from host into flash. The file should be encrypted
/// and signed.
fn handle_write(ctx: &mut Context, msg_len: usize) -> Result<(), ProtocolError> {
    if msg_len < size_of::<WriteFileHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // sizeof WriteFileHeader < CHUNK_SIZE
    let mut msg_buf = [0; CHUNK_SIZE];
    let msg = if msg_len < msg_buf.len() {
        &mut msg_buf[..msg_len]
    } else {
        &mut msg_buf
    };
    Message::send_ack(MessagePort::UART0);
    Message::read_body_no_ack(MessagePort::UART0, msg)?;

    let (header, data) = msg.split_at(core::mem::size_of::<WriteFileHeader>());
    let WriteFileHeader {
        pin,
        slot,
        group,
        name,
        uuid,
        length,
    } = *bytemuck::from_bytes(header);

    // check if the data from message is larger than allocated data/content area in fat, or whether
    // the allocated data has incorrect length
    let data_len = length as usize;
    if data_len > file::CONTENT_SIZE {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // TODO: check number of file slot requirements
    let slot = slot as usize;
    if slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    println!("1: {}", ctx.time());

    // retrieve signing and read encryption keys with pin
    let group_key = secrets::get_group_keys_from_pin(ctx, group, &pin)?;
    let pk_read = group_key.pk_read.ok_or(ProtocolError::InvalidGroup)?.0;

    println!("2: {}", ctx.time());

    // generate empty file variable
    let mut file = File::empty();
    file.state = File::FULL;

    // set file metadata
    let protected = &mut file.protected;
    protected.name = name;
    protected.uuid = uuid;
    protected.group = group;

    // set initial content data
    // we already verified that the data length is correct, so don't check again
    // TODO: do we need to read chunks?
    protected.contents.0[..data.len()].copy_from_slice(data);
    Message::send_ack(MessagePort::UART0);
    if data.len() < data_len {
        Message::read_body(
            MessagePort::UART0,
            &mut protected.contents.0[data.len()..data_len],
        )?;
    }

    protected.contents.0[data_len..].fill(0);
    protected.contents_length = data_len as u16;
    let ad = protected.associated_data();

    // encrypt everything
    encrypt_payload_pub(
        &mut protected.contents.0[..data_len],
        &mut protected.gn,
        &mut protected.nonce,
        &mut protected.tag,
        &pk_read,
        &ad,
    )?;

    let k_uuid = group_key.k_uuid.ok_or(ProtocolError::InvalidGroup)?;
    protected.uuid_ct_metadata =
        SymmetricMetadata::encrypt(bytemuck::bytes_of_mut(&mut protected.uuid), &k_uuid.0, &ad)?;

    println!("3: {}", ctx.time());
    let sk_sign = group_key.sk_sign.ok_or(ProtocolError::InvalidGroup)?;
    sign_file(&mut file, &sk_sign.0)?;
    println!("4: {}", ctx.time());

    // TODO: make sure file/fat can't be partially written
    let new_fat = FatEntry {
        uuid,
        length: data_len as u16,
        padding: 0,
        addr: ctx.fat.get().ok_or(ProtocolError::InvalidFile)?.entries[slot].addr,
    };

    // TODO: just write the one fat entry
    unsafe {
        ctx.files[slot]
            .set(&file)
            .map_err(|_| ProtocolError::StorageFailure)?;
    }
    println!("5: {}", ctx.time());
    let current = ctx.fat.get().ok_or(ProtocolError::InvalidFile)?;
    // avoid in-place mutation
    let mut entries = current.entries;
    entries[slot] = new_fat;
    unsafe {
        ctx.fat
            .set(&FatTable { entries })
            .map_err(|_| ProtocolError::StorageFailure)?;
    }
    println!("6: {}", ctx.time());

    Message::write(Opcode::Write, MessagePort::UART0, &[])?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ReceiveFileHeader {
    pub pin: [u8; 6],
    pub read_slot: u8,
    pub write_slot: u8,
}

fn handle_receive(ctx: &mut Context, msg_len: usize) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ReceiveFileHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ReceiveFileHeader>()];
    Message::send_ack(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ReceiveFileHeader {
        pin,
        read_slot,
        write_slot,
    } = *bytemuck::from_bytes(&msg);

    let k_auth = ctx.k_auth(&pin)?;

    // request file
    protocol::initiate_transfer(read_slot)?;

    // receive file
    let mut buf = [0u8; protocol::TRANSFER_RECEIVE_MAX_LENGTH];
    let response = Message::read(MessagePort::UART1, &mut buf)?;
    if response.opcode == Opcode::Error {
        return Err(ProtocolError::PeerBoardError);
    }
    if response.opcode != Opcode::Receive {
        return Err(ProtocolError::InvalidOpcode);
    }
    if response.length as usize != buf.len() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // decrypt with T1
    let payload = unwrap_symmetric_message(&mut buf, &TRANSFER_RECV.0, &[Opcode::Receive.into()])?;
    if payload.len() < size_of::<u16>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // parse out group id associated data
    let (assymetric_payload, group_id_bytes) =
        payload.split_at_mut(payload.len() - size_of::<u16>());
    let group_id_bytes: &mut [u8; 2] = group_id_bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessageLength)?;
    let group_id = u16::from_le_bytes(*group_id_bytes);

    // decrypt correct keys based on group
    let enc_group_keys = secrets::get_enc_group_keys(group_id)?;
    let group_keys = enc_group_keys.decrypt(&k_auth);

    // decrypt assymetrically encrypted part of message
    let inner = unwrap_pub_message(
        assymetric_payload,
        &group_keys.sk_trans.ok_or(ProtocolError::InvalidGroup)?.0,
        group_id_bytes,
    )?;

    if inner.len() != size_of::<File>() {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let file: &mut File = bytemuck::from_bytes_mut(inner);
    // check earlier associated group id matches
    if file.protected.group != group_id {
        return Err(ProtocolError::InvalidGroup);
    }

    verify_signature(file, &enc_group_keys.pk_sign.0)?;

    // decrypt uuid
    let mut uuid = file.protected.uuid;
    let ad = file.protected.associated_data();
    file.protected.uuid_ct_metadata.decrypt(
        bytemuck::bytes_of_mut(&mut uuid),
        &group_keys.k_uuid.ok_or(ProtocolError::InvalidGroup)?.0,
        &ad,
    )?;

    let write_slot = write_slot as usize;
    if write_slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    let new_fat = FatEntry {
        uuid,
        length: file.protected.contents_length,
        padding: 0,
        addr: ctx.fat.get().ok_or(ProtocolError::InvalidFile)?.entries[write_slot].addr,
    };

    // TODO: just write the one fat entry
    unsafe {
        ctx.files[write_slot]
            .set(file)
            .map_err(|_| ProtocolError::StorageFailure)?;
        let current = ctx.fat.get().ok_or(ProtocolError::InvalidFile)?;
        let mut entries = current.entries;
        entries[write_slot] = new_fat;
        ctx.fat
            .set(&FatTable { entries })
            .map_err(|_| ProtocolError::StorageFailure)?;
    }

    Message::write_header(Opcode::Receive, 0, MessagePort::UART0);
    Ok(())
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct InterrogateHeader {
    pub pin: [u8; 6],
}

/// Interrogate an adjacent board for a list of files that the current board
/// has permissions for. Since the entire list of files is encrypted
/// symmetrically and each file's metadata encrypted asymmetrically, all this
/// will be decrypted before being sent back to host.
fn handle_interrogate(ctx: &mut Context, msg_len: usize) -> Result<(), ProtocolError> {
    // Command contains just the PIN
    if msg_len != size_of::<InterrogateHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<InterrogateHeader>()];
    Message::send_ack(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let InterrogateHeader { pin } = *bytemuck::from_bytes(&msg);

    let _k_auth = ctx.k_auth(&pin)?;

    // TODO: maybe send bitmask
    const GROUPS_BYTE_LEN: usize = COPY_PERM_GROUPS.len() * size_of::<u16>();
    let mut buf = [0u8; GROUPS_BYTE_LEN + size_of::<SymmetricMetadata>()];
    let (payload, metadata) = buf.split_at_mut(GROUPS_BYTE_LEN);
    let metadata: &mut SymmetricMetadata = bytemuck::from_bytes_mut(metadata);

    // copy list of interrogatable groups
    payload.copy_from_slice(bytemuck::cast_slice(&COPY_PERM_GROUPS));

    // encrypt
    *metadata =
        SymmetricMetadata::encrypt(payload, &INTERROGATE_SEND.0, &[Opcode::Interrogate.into()])?;

    // send message
    Message::write(Opcode::Interrogate, MessagePort::UART1, &buf)?;

    // receive interrogate response
    let mut buf = [0u8; size_of::<EncryptedInterrogateInfo>() * 8 + size_of::<SymmetricMetadata>()];
    let response = Message::read(MessagePort::UART1, &mut buf)?;
    if response.opcode == Opcode::Error {
        return Err(ProtocolError::PeerBoardError);
    }
    if response.opcode != Opcode::Interrogate {
        return Err(ProtocolError::InvalidOpcode);
    }
    let payload = &mut buf[..response.length as usize];

    // decrypt
    let payload =
        unwrap_symmetric_message(payload, &INTERROGATE_RECV.0, &[Opcode::Interrogate.into()])?;
    let interrogate_info: &mut [EncryptedInterrogateInfo] = bytemuck::cast_slice_mut(payload);
    let count = interrogate_info.len();

    // allocate response buffer of the maximum size
    let mut response = [0; 4 + 8 * size_of::<listen::InterrogateFile>()];

    // split num_files off from the list and set it
    let (num_files, list) = response.split_at_mut(4);
    num_files.copy_from_slice(&(count as u32).to_le_bytes());

    for (i, ifile) in interrogate_info.iter_mut().enumerate() {
        let group_keys = secrets::get_enc_group_keys(ifile.file.group())?;

        ifile.decrypt(&group_keys.k_inter.0)?;

        // copy to the correct offset in list
        let list_offset = i * size_of::<listen::InterrogateFile>();
        let list_entry = &mut list[list_offset..list_offset + size_of::<listen::InterrogateFile>()];
        list_entry[0] = ifile.file.protected.slot;
        list_entry[1..3].copy_from_slice(&u16::to_le_bytes(ifile.file.group()));
        list_entry[3..].copy_from_slice(&ifile.file.protected.name.0);
    }

    let actual_message_size = 4 + count * size_of::<listen::InterrogateFile>();
    Message::write(
        Opcode::Interrogate,
        MessagePort::UART0,
        &response[..actual_message_size],
    )?;
    Ok(())
}

/// Listens for any Receive or Interrogate command from an adjacent board to
/// process before sending back the corresponding data.
fn handle_listen(ctx: &mut Context) -> Result<(), ProtocolError> {
    Message::send_ack(MessagePort::UART0);
    Message::write_header(Opcode::Listen, 0, MessagePort::UART0);
    let mut body = [0u8; MAX_BODY_SIZE];
    let msg = Message::read(MessagePort::UART1, &mut body)?;
    println!("listen: got message: {:?}", msg.opcode);
    listen::recv(ctx, msg.opcode, &mut body[..msg.length as usize])?;
    Ok(())
}

fn handle_listen_request(ctx: &mut Context) -> Result<(), ProtocolError> {
    if let Err(err) = handle_listen(ctx) {
        let _ = Message::write(Opcode::Error, MessagePort::UART1, &[]);
        Err(err)
    } else {
        Ok(())
    }
}
