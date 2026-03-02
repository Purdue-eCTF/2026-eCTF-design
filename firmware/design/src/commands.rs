use bytemuck::{Pod, Zeroable};

use crate::{
    context::*,
    crypto::{
        SymmetricMetadata, decrypt_payload_pub, encrypt_payload_pub, sign_file, unwrap_pub_message,
        unwrap_symmetric_message, verify_signature_bytes,
    },
    file::{self, File, FileMeta, FileName, UUID},
    listen::{self, EncryptedInterrogateInfo},
    message::{CHUNK_SIZE, MAX_BODY_SIZE, Message, MessagePort, Opcode},
    println,
    protocol::{self, ProtocolError},
    secrets::{
        self, COPY_PERM_GROUPS, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV,
        get_enc_group_keys,
    },
};

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ListHeader {
    pub pin: [u8; 6],
}

/// List files; requires pin on usage. Sends back a head with total number of
/// files and length of the message body, and then the data, with the name,
/// group, and slot of the file.
#[inline(never)]
fn handle_list(ctx: &mut Context, msg_len: usize, end_time: u32) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ListHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ListHeader>()];
    Message::send_ack(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ListHeader { pin } = *bytemuck::from_bytes(&msg);

    // check that PIN is correct before continuing
    let _k_auth = ctx.k_auth(&pin)?;

    handle_list_inner(ctx, end_time)
}

#[inline(never)]
fn handle_list_inner(ctx: &mut Context, end_time: u32) -> Result<(), ProtocolError> {
    // 4 bytes at start for total number of files; file slot, name of file, group id, for 8 files
    const METADATA_SIZE: usize = core::mem::size_of::<FileMeta>();
    let mut buffer = [0u8; 4 + 8 * METADATA_SIZE];
    let (num_files_buf, list_entries_buf) = buffer.split_at_mut(4);
    let list_entries: &mut [FileMeta; 8] = bytemuck::from_bytes_mut(list_entries_buf);
    let mut counter: usize = 0;
    for i in 0..8 {
        // if flash entry is empty, continue
        let Some(file) = ctx.files[i].get() else {
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
    num_files_buf.copy_from_slice(&(counter as u32).to_le_bytes());

    // return data without the extra space allocated in the body buffer

    // delay until UART is about to send
    while ctx.time() < end_time {}

    Message::write(
        Opcode::List,
        MessagePort::UART0,
        &buffer[..4 + counter * METADATA_SIZE],
    )
    .map_err(ProtocolError::Message)
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
#[inline(never)]
fn handle_read(ctx: &mut Context, msg_len: usize, end_time: u32) -> Result<(), ProtocolError> {
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

    let k_auth = ctx.k_auth(&pin)?;

    handle_read_inner(ctx, slot, &k_auth, end_time)
}

#[inline(never)]
fn handle_read_inner(
    ctx: &mut Context,
    slot: usize,
    k_auth: &[u8; 32],
    end_time: u32,
) -> Result<(), ProtocolError> {
    let file = ctx.files[slot].get().ok_or(ProtocolError::InvalidFile)?;
    let file_length = file.protected.contents_length as usize;

    // get group key and verify file hasn't been tampered
    let group = file.protected.group;
    let enc_group_keys = get_enc_group_keys(group)?;
    let group_key = enc_group_keys.decrypt(k_auth);
    let pk_sign = enc_group_keys.pk_sign.0;
    verify_signature_bytes(file, &pk_sign)?;

    // buf = N || PT
    let mut buffer = [0u8; file::NAME_SIZE + file::CONTENT_SIZE];
    let (name, protected) = buffer.split_at_mut(file::NAME_SIZE);
    name.copy_from_slice(&file.protected.name.0);
    protected[..file_length].copy_from_slice(&file.protected.contents.0[..file_length]);
    let ad = file.protected.associated_data();

    // decrypt the file into buffer
    let sk_read = group_key.sk_read.ok_or(ProtocolError::InvalidGroup)?;
    decrypt_payload_pub(
        &mut protected[..file_length],
        &file.protected.gn,
        &file.protected.nonce,
        &file.protected.tag,
        &sk_read.0,
        &ad,
    )?;

    let total_length = file::NAME_SIZE + file_length;

    // delay until UART is about to send
    while ctx.time() < end_time {}

    Message::write(Opcode::Read, MessagePort::UART0, &buffer[..total_length])
        .map_err(ProtocolError::Message)
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
#[inline(never)]
fn handle_write(ctx: &mut Context, msg_len: usize, end_time: u32) -> Result<(), ProtocolError> {
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
    let header: WriteFileHeader = *bytemuck::from_bytes(header);

    println!("1: {}", ctx.time());

    let k_auth = ctx.k_auth(&header.pin)?;

    println!("2: {}", ctx.time());

    handle_write_inner(ctx, header, data, &k_auth, end_time)
}

#[inline(never)]
fn handle_write_inner(
    ctx: &mut Context,
    header: WriteFileHeader,
    data: &[u8],
    k_auth: &[u8; 32],
    end_time: u32,
) -> Result<(), ProtocolError> {
    let WriteFileHeader {
        pin: _,
        slot,
        group,
        name,
        uuid,
        length,
    } = header;

    // check if the data from message is larger than allocated data/content area in fat, or whether
    // the allocated data has incorrect length
    let data_len = length as usize;
    if data_len > file::CONTENT_SIZE {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let slot = slot as usize;
    if slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    // retrieve signing and read encryption keys with pin
    let enc_group_keys = get_enc_group_keys(group)?;
    let group_key = enc_group_keys.decrypt(k_auth);
    let pk_read = group_key.pk_read.ok_or(ProtocolError::InvalidGroup)?.0;

    // start w/ empty file and fill in fields
    let mut file = File::empty();

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

    println!("2.5: {}", ctx.time());

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

    unsafe {
        ctx.files[slot]
            .set(&file)
            .map_err(|_| ProtocolError::StorageFailure)?;
    }
    println!("5: {}", ctx.time());
    ctx.rebuild_fat(k_auth)?;
    println!("6: {}", ctx.time());

    // delay until UART is about to send
    while ctx.time() < end_time {}

    Message::write(Opcode::Write, MessagePort::UART0, &[]).map_err(ProtocolError::Message)
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ReceiveFileHeader {
    pub pin: [u8; 6],
    pub read_slot: u8,
    pub write_slot: u8,
}

#[inline(never)]
fn handle_receive(ctx: &mut Context, msg_len: usize, end_time: u32) -> Result<(), ProtocolError> {
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

    println!("1: {}", ctx.time());

    let k_auth = ctx.k_auth(&pin)?;

    println!("2: {}", ctx.time());

    handle_receive_inner(ctx, read_slot, write_slot, &k_auth, end_time)
}

#[inline(never)]
fn handle_receive_inner(
    ctx: &mut Context,
    read_slot: u8,
    write_slot: u8,
    k_auth: &[u8; 32],
    end_time: u32,
) -> Result<(), ProtocolError> {
    // request file
    protocol::initiate_transfer(read_slot)?;

    println!("3: {}", ctx.time());

    // receive file
    let mut buffer = [0u8; protocol::TRANSFER_RECEIVE_MAX_LENGTH];
    let response = Message::read(MessagePort::UART1, &mut buffer)?;
    match response.opcode {
        Opcode::Error => return Err(ProtocolError::PeerBoardError),
        Opcode::Receive => (),
        _ => return Err(ProtocolError::InvalidOpcode),
    };

    if response.length as usize != buffer.len() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // time to receive after request sent: ~1.8 seconds
    println!("4: {}", ctx.time());

    // decrypt with T1
    let payload =
        unwrap_symmetric_message(&mut buffer, &TRANSFER_RECV.0, &[Opcode::Receive.into()])?;
    if payload.len() < size_of::<u16>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // parse out group id associated data
    let (asymmetric_payload, group_id_bytes) =
        payload.split_at_mut(payload.len() - size_of::<u16>());
    let group_id_bytes: &mut [u8; 2] = group_id_bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessageLength)?;
    let group_id = u16::from_le_bytes(*group_id_bytes);

    println!("5: {}", ctx.time());

    // decrypt correct keys based on group
    let enc_group_keys = secrets::get_enc_group_keys(group_id)?;
    let group_keys = enc_group_keys.decrypt(k_auth);

    println!("6: {}", ctx.time());

    // decrypt asymmetrically encrypted part of message
    // about ~0.75-0.8 seconds
    let inner = unwrap_pub_message(
        asymmetric_payload,
        &group_keys.sk_trans.ok_or(ProtocolError::InvalidGroup)?.0,
        group_id_bytes,
    )?;

    println!("7: {}", ctx.time());

    if inner.len() != size_of::<File>() {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let file: &mut File = bytemuck::from_bytes_mut(inner);
    // check earlier associated group id matches
    if file.protected.group != group_id {
        return Err(ProtocolError::InvalidGroup);
    }

    // verify takes about 0.7 seconds
    verify_signature_bytes(file, &enc_group_keys.pk_sign.0)?;

    println!("8: {}", ctx.time());

    let write_slot = write_slot as usize;
    if write_slot > 7 {
        return Err(ProtocolError::InvalidSlot);
    }

    println!("9: {}", ctx.time());

    unsafe {
        ctx.files[write_slot]
            .set(file)
            .map_err(|_| ProtocolError::StorageFailure)?;
        println!("10: {}", ctx.time());
    }
    ctx.rebuild_fat(k_auth)?;
    // 0.08 seconds total writing flash
    println!("11: {}", ctx.time());

    // delay until UART is about to send
    while ctx.time() < end_time {}

    Message::write(Opcode::Receive, MessagePort::UART0, &[]).map_err(ProtocolError::Message)
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
#[inline(never)]
fn handle_interrogate(
    ctx: &mut Context,
    msg_len: usize,
    end_time: u32,
) -> Result<(), ProtocolError> {
    // Command contains just the PIN
    if msg_len != size_of::<InterrogateHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<InterrogateHeader>()];
    Message::send_ack(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let InterrogateHeader { pin } = *bytemuck::from_bytes(&msg);

    println!("1: {}", ctx.time());

    // check that PIN is correct before continuing
    let _k_auth = ctx.k_auth(&pin)?;

    println!("2: {}", ctx.time());

    handle_interrogate_inner(ctx, end_time)
}

#[inline(never)]
fn handle_interrogate_inner(ctx: &mut Context, end_time: u32) -> Result<(), ProtocolError> {
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

    println!("3: {}", ctx.time());

    // send message
    Message::write(Opcode::Interrogate, MessagePort::UART1, &buf)?;

    println!("4: {}", ctx.time());

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

    println!("5: {}", ctx.time());

    // decrypt
    let payload =
        unwrap_symmetric_message(payload, &INTERROGATE_RECV.0, &[Opcode::Interrogate.into()])?;
    let interrogate_info: &mut [EncryptedInterrogateInfo] = bytemuck::cast_slice_mut(payload);
    let count = interrogate_info.len();

    println!("6: {}", ctx.time());

    // allocate response buffer of the maximum size
    let mut buffer = [0u8; 4 + 8 * size_of::<listen::InterrogateFile>()];
    let response = &mut buffer;

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

    println!("7: {}", ctx.time());

    let actual_message_size = 4 + count * size_of::<listen::InterrogateFile>();

    // delay until UART is about to send
    while ctx.time() < end_time {}

    Message::write(
        Opcode::Interrogate,
        MessagePort::UART0,
        &buffer[..actual_message_size],
    )
    .map_err(ProtocolError::Message)
}

/// Listens for any Receive or Interrogate command from an adjacent board to
/// process before sending back the corresponding data.
#[inline(never)]
fn handle_listen(ctx: &mut Context) -> Result<(), ProtocolError> {
    let mut buffer = [0u8; MAX_BODY_SIZE];
    Message::send_ack(MessagePort::UART0);
    let msg = Message::read(MessagePort::UART1, &mut buffer)?;
    println!("listen: got message: {:?}", msg.opcode);
    listen::recv(ctx, msg.opcode, &mut buffer[..msg.length as usize])?;
    Ok(())
}

#[inline(never)]
fn handle_listen_request(ctx: &mut Context, end_time: u32) -> Result<(), ProtocolError> {
    if let Err(err) = handle_listen(ctx) {
        let _ = Message::write(Opcode::Error, MessagePort::UART1, &[]);
        // returning error will cause uart0 to have error written
        Err(err)
    } else {
        // handle listen has already sent a success response to uart1
        // delay until UART is about to send
        while ctx.time() < end_time {}

        Message::write(Opcode::Listen, MessagePort::UART0, &[]).map_err(ProtocolError::Message)
    }
}

/// convenience function to wait until the last second to send the response over UART
pub fn delayed_write(opcode: Opcode, ctx: &mut Context, msg_len: usize) {
    // since we're just using as a timer, we don't want it to overflow
    // and we don't really care about sub-ms accuracy
    ctx.reset_time();
    let start = ctx.time();

    let Budget(_, max_time, max_bytes) = TIME_BUDGET_MS.iter().find(|b| b.0 == opcode).unwrap();
    let uart_time = (max_bytes * 5700) >> 16; // approximately * 0.0868

    // end with enough time to send uart (plus 210ms margin
    // because timing doesn't include list start, etc)
    let uart_end = (start + max_time)
        .saturating_sub(uart_time)
        .saturating_sub(210);

    let res = match opcode {
        Opcode::List => handle_list(ctx, msg_len, uart_end),
        Opcode::Read => handle_read(ctx, msg_len, uart_end),
        Opcode::Write => handle_write(ctx, msg_len, uart_end),
        Opcode::Receive => handle_receive(ctx, msg_len, uart_end),
        Opcode::Interrogate => handle_interrogate(ctx, msg_len, uart_end),
        Opcode::Listen => handle_listen_request(ctx, uart_end),
        Opcode::Ack => {
            while ctx.time() < uart_end {}
            Message::write(opcode, MessagePort::UART0, &[]).map_err(ProtocolError::Message)
        }
        e @ (Opcode::Error | Opcode::Debug) => panic!("{e:?} should not be sent to board"),
    };

    if let Err(e) = res {
        panic!("handler failed: {e}");
    }

    while ctx.time() < start + max_time {}
}

// opcode, total budget, max uart bytes sent
pub struct Budget(pub Opcode, pub u32, pub u32);

pub const TIME_BUDGET_MS: &[Budget] = &[
    Budget(Opcode::List, 500, 288),
    Budget(Opcode::Read, 3000, 8228),
    Budget(Opcode::Write, 3000, 4),
    Budget(Opcode::Receive, 3000, 4),
    Budget(Opcode::Listen, 3000, 4),
    Budget(Opcode::Interrogate, 1000, 0),
];
