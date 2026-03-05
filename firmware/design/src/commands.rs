use core::time::Duration;

use bytemuck::{Pod, Zeroable};
use common::SymmetricKey;
use design_macros::rand_ops;
use ed25519_dalek::VerifyingKey;
use mspm0l222x_hal::{timer::Instant, trng};

use crate::{
    context::*,
    crypto::{
        PubKeyMetadata, SymmetricMetadata, decrypt_payload_symmetric, derive_assymetric_key,
        sign_file, verify_signature, verify_signature_bytes,
    },
    file::{self, File, FileMeta, FileName, UUID},
    listen,
    message::{self, CHUNK_SIZE, Message, MessagePort, Opcode},
    protocol::{self, ProtocolError, SafeError, SymEncryptable},
    secrets::{
        self, COPY_PERM_GROUPS, INTERROGATE_RECV, INTERROGATE_SEND, TRANSFER_RECV, TRANSFER_SEND,
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
///
/// See the protocol document for more detailed information on the cryptographic measures implemented.
#[inline(never)]
fn handle_list(ctx: &mut Context, msg_len: usize, end: Instant) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ListHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ListHeader>()];
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ListHeader { pin } = *bytemuck::from_bytes(&msg);

    // check that PIN is correct before continuing
    let _k_auth = ctx.k_auth(&pin)?;

    handle_list_inner(ctx, end)
}

#[inline(never)]
fn handle_list_inner(ctx: &mut Context, end: Instant) -> Result<(), ProtocolError> {
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

    while Instant::now() < end {}

    let result = Message::write(
        Opcode::List,
        MessagePort::UART0,
        &buffer[..4 + counter * METADATA_SIZE],
    )
    .map_err(ProtocolError::Message);

    result
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ReadFileHeader {
    pub pin: [u8; 6],
    pub slot: u8,
}

/// Read file on given slot, returning to the host the file; requires pin on
/// usage. Since the file is stored on flash encrypted, this function uses the
/// pin to decrypt the file before returning it to the host.
///
/// See the protocol document for more detailed information on the cryptographic measures implemented.
#[inline(never)]
fn handle_read(ctx: &mut Context, msg_len: usize, end: Instant) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ReadFileHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ReadFileHeader>()];
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ReadFileHeader { pin, slot } = *bytemuck::from_bytes(&msg);
    let slot = slot as usize;

    if slot > 7 {
        return Err(SafeError::InvalidSlot.into());
    }

    let k_auth = ctx.k_auth(&pin)?;

    handle_read_inner(ctx, slot, &k_auth, end)
}

#[inline(never)]
fn handle_read_inner(
    ctx: &mut Context,
    slot: usize,
    k_auth: &SymmetricKey,
    end: Instant,
) -> Result<(), ProtocolError> {
    let file = ctx.files[slot]
        .get()
        .ok_or(ProtocolError::SafeError(SafeError::InvalidSlot))?;
    let file_length = file.protected.contents_length as usize;

    // get group key and verify file hasn't been tampered
    let group = file.protected.group;
    let enc_group_keys = get_enc_group_keys(group)?;
    let group_key = enc_group_keys.decrypt(k_auth);

    let pk_sign = enc_group_keys.pk_sign;
    verify_signature_bytes(file, &pk_sign)?;

    // buf = N || PT
    let mut buffer = [0u8; file::NAME_SIZE + file::CONTENT_SIZE];
    let (name, protected) = buffer.split_at_mut(file::NAME_SIZE);
    name.copy_from_slice(&file.protected.name.0);
    protected[..file_length].copy_from_slice(&file.protected.contents.0[..file_length]);
    let ad = file.protected.associated_data();

    // decrypt the file into buffer
    let sk_read = group_key.sk_read.ok_or(SafeError::InvalidGroup)?;
    file.protected
        .contents_ct_metadata
        .decrypt(&mut protected[..file_length], &sk_read, &ad)?;

    while Instant::now() < end {}

    let result = Message::write(
        Opcode::Read,
        MessagePort::UART0,
        &buffer[..file::NAME_SIZE + file_length],
    )
    .map_err(ProtocolError::Message);

    result
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
fn handle_write(ctx: &mut Context, msg_len: usize, end: Instant) -> Result<(), ProtocolError> {
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
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    Message::read_body_no_ack(MessagePort::UART0, msg)?;

    let (header, data) = msg.split_at(core::mem::size_of::<WriteFileHeader>());
    let header: WriteFileHeader = *bytemuck::from_bytes(header);

    let k_auth = ctx.k_auth(&header.pin)?;

    handle_write_inner(ctx, header, data, &k_auth, end)
}

#[inline(never)]
fn handle_write_inner(
    ctx: &mut Context,
    header: WriteFileHeader,
    data: &[u8],
    k_auth: &SymmetricKey,
    end: Instant,
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
        return Err(SafeError::InvalidSlot.into());
    }

    // start w/ empty file and fill in fields
    let mut file = File::empty();

    // set file metadata
    let protected = &mut file.protected;
    protected.name = name;
    protected.uuid = uuid;
    protected.group = group;

    // set initial content data
    // we already verified that the data length is correct, so don't check again
    protected.contents.0[..data.len()].copy_from_slice(data);
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    if data.len() < data_len {
        Message::read_body(
            MessagePort::UART0,
            &mut protected.contents.0[data.len()..data_len],
        )?;
    }
    // if no extra data read, need rand ops after ack with no rand ops
    rand_ops!(trng::trng());

    protected.contents.0[data_len..].fill(0);
    protected.contents_length = data_len as u16;
    let ad = protected.associated_data();

    // retrieve signing and read encryption keys with k_auth
    let enc_group_keys = get_enc_group_keys(group)?;
    let group_key = enc_group_keys.decrypt(k_auth);

    // encrypt everything
    let pk_read = group_key.pk_read.ok_or(SafeError::InvalidGroup)?;
    protected.contents_ct_metadata =
        PubKeyMetadata::encrypt(&mut protected.contents.0[..data_len], &pk_read, &ad)?;

    let k_uuid = group_key.k_uuid.ok_or(SafeError::InvalidGroup)?;
    protected.uuid_ct_metadata =
        SymmetricMetadata::encrypt(bytemuck::bytes_of_mut(&mut protected.uuid), &k_uuid, &ad)?;

    let sk_sign = group_key.sk_sign.ok_or(SafeError::InvalidGroup)?;
    sign_file(&mut file, &sk_sign)?;

    unsafe {
        ctx.files[slot]
            .set(&file)
            .map_err(|_| ProtocolError::StorageFailure)?;
    }
    ctx.rebuild_fat(k_auth)?;

    while Instant::now() < end {}

    let result =
        Message::write(Opcode::Write, MessagePort::UART0, &[]).map_err(ProtocolError::Message);

    result
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
    end: Instant,
) -> Result<(), ProtocolError> {
    // Command contains just the PIN
    if msg_len != size_of::<InterrogateHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<InterrogateHeader>()];
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let InterrogateHeader { pin } = *bytemuck::from_bytes(&msg);

    // check that PIN is correct before continuing
    let _k_auth = ctx.k_auth(&pin)?;

    handle_interrogate_inner(ctx, end)
}

#[inline(never)]
fn handle_interrogate_inner(_ctx: &mut Context, end: Instant) -> Result<(), ProtocolError> {
    if COPY_PERM_GROUPS.len() > protocol::INTERROGATE_MAX_GROUPS {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut request = protocol::EncryptedInterrogateRequest::zeroed();
    request.protected.group_count = COPY_PERM_GROUPS.len() as u8;
    for (dst, group_id) in request
        .protected
        .groups
        .iter_mut()
        .zip(COPY_PERM_GROUPS.iter().copied())
    {
        dst.set(group_id);
    }
    request.encrypt(&INTERROGATE_SEND)?;

    // send message
    Message::write(
        Opcode::Interrogate,
        MessagePort::UART1,
        bytemuck::bytes_of(&request),
    )?;

    // receive interrogate response
    let mut buf = [0u8; size_of::<protocol::EncryptedInterrogateResponse>()];
    let response = Message::read(MessagePort::UART1, &mut buf)?;

    match response.opcode {
        Opcode::Error => return Err(ProtocolError::PeerBoardError),
        Opcode::Interrogate => (),
        _ => return Err(SafeError::InvalidOpcode.into()),
    };
    if response.length as usize != buf.len() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // decrypt
    let interrogate_response: &mut protocol::EncryptedInterrogateResponse =
        bytemuck::from_bytes_mut(&mut buf);
    interrogate_response.decrypt(&INTERROGATE_RECV)?;

    let count = interrogate_response.protected.file_count as usize;
    if count > protocol::MAX_NUM_FILES {
        return Err(ProtocolError::InvalidMessageLength);
    }

    // allocate response buffer of the maximum size
    let mut buffer = [0u8; 4 + protocol::MAX_NUM_FILES * size_of::<FileMeta>()];
    let response = &mut buffer;

    // split num_files off from the list and set it
    let (num_files, list) = response.split_at_mut(4);
    num_files.copy_from_slice(&(count as u32).to_le_bytes());
    let list: &mut [FileMeta; protocol::MAX_NUM_FILES] = bytemuck::from_bytes_mut(list);

    for (dst, ifile) in list
        .iter_mut()
        .zip(interrogate_response.protected.files[..count].iter_mut())
    {
        let group_id = ifile.group_id.get();
        let group_keys = secrets::get_enc_group_keys(group_id)?;

        ifile.decrypt(&group_keys.k_inter)?;

        *dst = FileMeta {
            slot: ifile.protected.slot,
            group: group_id,
            name: ifile.protected.name,
        };
    }

    let actual_message_size = 4 + count * size_of::<FileMeta>();

    while Instant::now() < end {}

    let result = Message::write(
        Opcode::Interrogate,
        MessagePort::UART0,
        &buffer[..actual_message_size],
    )
    .map_err(ProtocolError::Message);

    result
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed)]
struct ReceiveFileHeader {
    pub pin: [u8; 6],
    pub read_slot: u8,
    pub write_slot: u8,
}

#[inline(never)]
fn handle_receive(ctx: &mut Context, msg_len: usize, end: Instant) -> Result<(), ProtocolError> {
    if msg_len != size_of::<ReceiveFileHeader>() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let mut msg = [0; size_of::<ReceiveFileHeader>()];
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    Message::read_body(MessagePort::UART0, &mut msg)?;

    let ReceiveFileHeader {
        pin,
        read_slot,
        write_slot,
    } = *bytemuck::from_bytes(&msg);

    let k_auth = ctx.k_auth(&pin)?;

    handle_receive_inner(ctx, read_slot, write_slot, &k_auth, end)
}

#[inline(never)]
fn handle_receive_inner(
    ctx: &mut Context,
    read_slot: u8,
    write_slot: u8,
    k_auth: &SymmetricKey,
    end: Instant,
) -> Result<(), ProtocolError> {
    let write_slot = write_slot as usize;
    if write_slot > 7 {
        return Err(SafeError::InvalidSlot.into());
    }

    // request file
    let mut request = protocol::EncryptedTransferRequest {
        protected: protocol::TransferRequest::new(read_slot),
        metadata: SymmetricMetadata::empty(),
    };
    request.encrypt(&TRANSFER_SEND)?;

    Message::write(
        Opcode::Receive,
        MessagePort::UART1,
        bytemuck::bytes_of(&request),
    )?;

    // receive file
    let mut buffer = [0u8; size_of::<protocol::EncryptedTransferResponseHeader>()];
    let response = Message::read(MessagePort::UART1, &mut buffer)?;

    match response.opcode {
        Opcode::Error => return Err(ProtocolError::PeerBoardError),
        Opcode::Receive => (),
        _ => return Err(SafeError::InvalidOpcode.into()),
    };
    if response.length as usize != buffer.len() {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let header: &mut protocol::EncryptedTransferResponseHeader =
        bytemuck::from_bytes_mut(&mut buffer);
    // store copy for later
    let header_ct = *header;
    header.decrypt(&TRANSFER_RECV)?;
    let group_id = header.protected.group_id.get();

    let enc_group_keys = secrets::get_enc_group_keys(group_id)?;
    let group_keys = enc_group_keys.decrypt(k_auth);
    // verify we have sk_trans which means we have copy perms before starting async recv
    let Some(sk_trans) = group_keys.sk_trans else {
        Message::send_error_no_ack(MessagePort::UART1);
        return Err(SafeError::InvalidGroup.into());
    };

    // start async recv only after the header has been validated and the local
    // receive keys are confirmed to exist, otherwise a rejected receive can
    // leave UART1's async path armed for later commands.
    message::start_async_recv(size_of::<protocol::EncryptedTransferResponseBody>());
    Message::send_ack(MessagePort::UART1);

    // decrypt correct keys based on group
    let verifying_key = VerifyingKey::from_bytes(&enc_group_keys.pk_sign.0).unwrap();

    // while file data is being received, derive the shared secret used for the inner payload

    let shared_secret = derive_assymetric_key(&sk_trans.0, &header.protected.pub_metadata.gn);

    // receive body of message
    let mut body = protocol::EncryptedTransferResponseBody::zeroed();
    message::await_async_recv_done(bytemuck::bytes_of_mut(&mut body));

    // decrypt outer file data
    body.decrypt_with_associated_data(&TRANSFER_RECV, bytemuck::bytes_of(&header_ct))?;

    // decrypt inner assymetric data
    decrypt_payload_symmetric(
        bytemuck::bytes_of_mut(&mut body.protected),
        &header.protected.pub_metadata.nonce,
        &header.protected.pub_metadata.tag,
        &shared_secret,
        bytemuck::bytes_of(&group_id.to_le_bytes()),
    )?;

    // check inner file data
    let file = &body.protected;
    if file.protected.group != group_id {
        return Err(SafeError::InvalidGroup.into());
    }

    // verify takes about 0.7 seconds
    verify_signature(file, &verifying_key)?;

    unsafe {
        ctx.files[write_slot]
            .set(file)
            .map_err(|_| ProtocolError::StorageFailure)?;
    }
    ctx.rebuild_fat(k_auth)?;

    while Instant::now() < end {}

    let result =
        Message::write(Opcode::Receive, MessagePort::UART0, &[]).map_err(ProtocolError::Message);

    result
}

/// Listens for any Receive or Interrogate command from an adjacent board to
/// process before sending back the corresponding data.
#[inline(never)]
fn handle_listen(ctx: &mut Context) -> Result<(), ProtocolError> {
    let mut buffer = [0u8; 1024];
    Message::send_ack_no_rand_ops(MessagePort::UART0);
    let msg = Message::read(MessagePort::UART1, &mut buffer)?;
    listen::recv(ctx, msg.opcode, &mut buffer[..msg.length as usize])?;
    Ok(())
}

#[inline(never)]
fn handle_listen_request(ctx: &mut Context, end: Instant) -> Result<(), ProtocolError> {
    match handle_listen(ctx) {
        Ok(_) => {
            // handle listen has already sent a success response to uart1, send uart0 success
            Message::write(Opcode::Listen, MessagePort::UART0, &[]).map_err(ProtocolError::Message)
        }
        e @ Err(ProtocolError::SafeError(_)) => {
            Message::send_safe_error_no_ack(MessagePort::UART1);
            e
        }
        e @ Err(_) => {
            Message::send_error_no_ack(MessagePort::UART1);
            e
        }
    }
}

/// convenience function to dispatch to an appropriate command
pub fn handle_any(opcode: Opcode, ctx: &mut Context, msg_len: usize) {
    let start = Instant::now();

    let Some(Budget(_, max_time, max_bytes)) = TIME_BUDGET_MS.iter().find(|b| b.0 == opcode) else {
        // received random ack, ignore
        return;
    };
    let uart_time = (max_bytes * 5700) >> 16; // approximately * 0.0868
    let operation_time = max_time.saturating_sub(uart_time).saturating_sub(50);

    let end = start + Duration::from_millis(operation_time as u64);

    let res = match opcode {
        Opcode::List => handle_list(ctx, msg_len, end),
        Opcode::Read => handle_read(ctx, msg_len, end),
        Opcode::Write => handle_write(ctx, msg_len, end),
        Opcode::Receive => handle_receive(ctx, msg_len, end),
        Opcode::Interrogate => handle_interrogate(ctx, msg_len, end),
        Opcode::Listen => handle_listen_request(ctx, end),
        Opcode::Ack => {
            Message::write(opcode, MessagePort::UART0, &[]).map_err(ProtocolError::Message)
        }
        e @ (Opcode::Error | Opcode::Debug | Opcode::SafeError) => {
            panic!("{e:?} should not be sent to board")
        }
    };

    if opcode != Opcode::Listen {
        while Instant::now() < end {}
    }

    match res {
        Ok(_) => (),
        Err(ProtocolError::SafeError(e)) => crate::eprintln!("error: {e}"),
        Err(e) => panic!("handler failed: {e}"),
    }

    // no need to delay, because if the command succeeded, there wasn't any issue
    // and it restarts if it panicked
}

// opcode, total budget, max uart bytes sent
pub struct Budget(pub Opcode, pub u32, pub u32);

pub const TIME_BUDGET_MS: &[Budget] = &[
    Budget(Opcode::List, 500, 288),
    Budget(Opcode::Read, 2960, 8228),
    Budget(Opcode::Write, 2950, 4),
    // 50 ms safety
    Budget(Opcode::Receive, 2950, 4),
    Budget(Opcode::Listen, 3000, 4),
    Budget(Opcode::Interrogate, 1000, 288),
];
