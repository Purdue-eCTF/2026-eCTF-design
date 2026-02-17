#![no_std]
#![no_main]

mod crypto;
mod listen;
mod message;
mod secrets;
mod view;

use bytemuck::{Pod, Zeroable};
use core::panic::PanicInfo;
use cortex_m_rt::entry;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey, Signer};

use view::{MutFileView, FileView};

use mspm0l222x_hal::{
    Peripherals, flash::FlashController, iomux::Iomux, led::Led, trng::Trng, uart::{Uart0, println, uart1}
};

use crate::{crypto::{decrypt_payload_pub, decrypt_payload_symmetric, encrypt_payload_pub, encrypt_payload_symmetric, NONCE_SIZE, TAG_SIZE}, message::{Message, Opcode}, secrets::{SymmetricKey}, view::{DATA_OFFSET, MutFile, NAME_OFFSET}};

use message::MessagePort;

unsafe extern "C" {
    static _stack_start: u8;
    static _boot_salt: u8;
    static _files: u8;
    static _filetable: u8;
}

#[panic_handler]
fn handle_panics(info: &PanicInfo) -> ! {
    println!("{info}");
    cortex_m::peripheral::SCB::sys_reset();
}

// TODO: glitching prevention or similar
// TODO: how badly will this hit flash? Can we rotate slots or something?
macro_rules! sensitive {
    ($context:ident, $($body:stmt)+) => {
        $context.move_salt_to_ram();
        $($body)+
        $context.move_salt_to_flash();
    };
}

#[repr(C)]
pub struct File {
    contents: [u8; 8192],
}

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
struct FatEntry {
    uuid: [u8; 16],
    length: u16,
    padding: u16,
    addr: usize,
}

use view::{NAME_SIZE, GID_SIZE, UUID_SIZE, MAX_FILE_SIZE, SIGNATURE_SIZE, MAX_CONTENT_SIZE};

#[derive(Debug)]
pub enum FileViewError {
    BufferTooSmall,
}

// TODO: move File/FatEntry to FlashEntry abstraction
pub(crate) struct Context {
    pub files: &'static [File; 8],
    pub fat: &'static [FatEntry; 8],
    pub flash: FlashController,
}

impl Context {
    pub(crate) fn new(peripherals: Peripherals) -> Self {
        // TODO: PIN salt generation + penalty enforcement
        // TODO: check for flash write failure
        let iomux = Iomux::new(&peripherals.iomux);
        Uart0::init(&iomux, peripherals.uart0);
        // init Uart1?
        Led::init(&iomux, peripherals.gpioa, peripherals.gpiob);
        Trng::init(peripherals.trng);
        let files = unsafe { core::mem::transmute(&_files) };
        let fat = unsafe { core::mem::transmute(&_filetable) };
        let flash = FlashController::new(peripherals.flashctl);
        Self { files, fat, flash }
    }

    pub(crate) fn move_salt_to_ram(&self) {}
    pub(crate) fn move_salt_to_flash(&self) {}
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

    for i in (0..8 * 1024).step_by(1024) {
        unsafe {
            ctx.flash
                .write_page((&ctx.files[0] as *const File) as u32 + i, &[0u8; 1024])
                .unwrap();
        }
    }

    println!("{:?}", &ctx.files[0].contents[0..10]);

    loop {
        let msg = Message::read(MessagePort::UART0).unwrap();

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
    slot: [u8; 1],
    name: [u8; NAME_SIZE],
    group: [u16; 1],
    _pad: [u8; 1]

}

// TODO
fn handle_list(ctx: &mut Context) {
    // 4 bytes at start for total number of files; file slot, name of file, group id, padding, for 8 files
    let mut list: [u8; 4 + 1 + NAME_SIZE + 2 + 1] = [0u8; 4 + 1 + NAME_SIZE + 2 + 1]; 
    let mut counter: usize = 0;
    // index * info + newline + file slot
    const METADATA_SIZE: usize = 1 + NAME_SIZE + 2 + 1;

    // - slot, file name, group ids, newline
    for i in 0..8 {
        // name | groupid | uuid | data
        // if not in use, continue
        let file = FileView::from_file(&ctx.files[i].contents, ctx.fat[i].length as usize);
        if !file.exists { continue; }

        // file slot
        list[(counter * METADATA_SIZE)..((counter * METADATA_SIZE) + 1usize)].copy_from_slice(&[i as u8]);
        // if it looks like a struct and it quacks like a struct then surely it's a struct
        let metadata: ListEntry = ListEntry { slot: [i as u8], name: *file.name, group: [file.group], _pad: [10u8] };

        // read guid
        // is this fine
        list[4usize + (counter * METADATA_SIZE).. 4usize + (counter * METADATA_SIZE) + METADATA_SIZE].copy_from_slice(bytemuck::bytes_of(&metadata));

        counter += 1;
        // guid + \t + name
    }
    list[0..1].copy_from_slice(&[counter as u8]);
    let body = if list.iter().all(|&byte| byte == 0) {"No files found.".as_bytes()} else {&list};

    // PRAYING THIS WORKS (TODO does result need to be used)
    Message::send_data(Opcode::List, body, MessagePort::UART0).unwrap();
    
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

    let file_length = ctx.fat[slot].length as usize;
    let fv = FileView::from_file(&ctx.files[slot].contents, file_length);
    if !fv.exists {
        panic!()
    }

    let group = fv.group;
    let group_key = get_group_key(group, &pin).unwrap();
    let pk_sign = VerifyingKey::from_bytes(&group_key.pk_sign.0).unwrap();
    fv.verify_signature(&pk_sign).unwrap();

    let mut buf: [u8; MAX_FILE_SIZE] = [0u8; _];
    let _ = fv.copy_to_buf(&mut buf).unwrap();

    crypto::decrypt_payload_pub_combined(&mut buf[DATA_OFFSET..MAX_FILE_SIZE - 1], &group_key.sk_read.0).unwrap();

    let data = fv.data;

    let total_length = view::NAME_SIZE + data.len();
    let mut body = [0u8; message::CHUNK_SIZE];

    message::Message::write_header_helper(Opcode::Read, total_length.try_into().unwrap(), MessagePort::UART0);

    let eat = if total_length <= message::CHUNK_SIZE {
        data.len()
    } else {
        message::CHUNK_SIZE - NAME_SIZE
    };

    let (initial, rest) = data.split_at(eat);
    body[..view::NAME_SIZE].copy_from_slice(fv.name);
    body[view::NAME_SIZE..view::NAME_SIZE + eat].copy_from_slice(initial);
    message::Message::write_block(&body[..message::CHUNK_SIZE], MessagePort::UART0).unwrap();

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
    let (group_id, rest) = rest.split_at(GID_SIZE);
    let (name, rest) = rest.split_at(NAME_SIZE);
    let (uuid, rest) = rest.split_at(UUID_SIZE);
    let (length, data) = rest.split_at(2);


    let data_len = u16::from_le_bytes(length.try_into().unwrap()) as usize;
    if data_len > MAX_CONTENT_SIZE {
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

    let data_len = u16::from_le_bytes(length.try_into().unwrap()) as usize;

    let mut buf: [u8; NONCE_SIZE + MAX_FILE_SIZE + TAG_SIZE] = [0u8; NONCE_SIZE + MAX_FILE_SIZE + TAG_SIZE];
    {
        let cv = MutFileView::new(&mut buf).unwrap();
        cv.name.copy_from_slice(name);
        cv.group.copy_from_slice(&group.to_le_bytes());
        cv.uuid.copy_from_slice(uuid);
    }

    let sig: Signature = sk_sign.sign(&buf[NAME_OFFSET..DATA_OFFSET]);
    buf[..SIGNATURE_SIZE].copy_from_slice(&sig.to_bytes());

    let first = core::cmp::min(data_len, data.len());
    let mut offset = DATA_OFFSET;
    buf[offset..offset + first].copy_from_slice(&data[..first]);
    offset += first;

    while offset < data_len {
        let block = Message::read_block(MessagePort::UART0).unwrap();
        let take = core::cmp::min(data_len - offset, block.len());
        buf[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }

    buf[offset..MAX_FILE_SIZE - 1].fill(0);
    buf[MAX_FILE_SIZE - 1] = 1;
    // TODO
    encrypt_payload_pub(&mut buf[DATA_OFFSET..DATA_OFFSET + data_len], &mut buf[0..DATA_OFFSET], &mut , &pk_read).unwrap();
    
    let new_fat = FatEntry {
        uuid: uuid.try_into().unwrap(),
        length: data_len as u16,
        padding: ctx.fat[slot].padding, // what is this?
        addr: ctx.fat[slot].addr,
    };

    const PAGE_SIZE: usize = 1024;
    for page_idx in 0..(MAX_FILE_SIZE / PAGE_SIZE) {
        let offset = page_idx * PAGE_SIZE;
        let page: &[u8; PAGE_SIZE] = buf[offset..offset + PAGE_SIZE].try_into().unwrap();
        unsafe {
            ctx.flash
                .write_page((&ctx.files[slot] as *const File) as u32 + offset as u32, page)
                .unwrap();
        }
    }

    let fat_slice = bytemuck::bytes_of(&new_fat);
    for i in 0..(size_of::<FatEntry>() / 8) {
        let offset = i * 8;
        unsafe {
            ctx.flash.write_word(
                &ctx.fat[slot] as *const FatEntry as u32 + offset as u32,
                &fat_slice[offset..offset + 8].try_into().unwrap()
            ).unwrap();
        }
    }
}

fn handle_receive(ctx: &mut Context) {
    todo!()
}

// TODO
fn handle_interrogate(ctx: &mut Context) {
    // check for right pin from host
    // - if not right pin, panic w message

    let mut groups: [u8; secrets::GROUP_KEYS.len() * GID_SIZE] = [0u8; secrets::GROUP_KEYS.len() * GID_SIZE];
    let mut group_count = 0;
    // TODO retrieve perms. if group's key is loaded into flash, add group?
    // concatenate all groups that have perms (GID_SIZE = 2, or 16 bits)
    for group in secrets::GROUP_KEYS.iter().enumerate() {
        if group.1.pk_inter.0.is_empty() { continue };
        group_count += 1;
        groups[group_count * GID_SIZE..(group_count * GID_SIZE + GID_SIZE)].copy_from_slice(&group.1.group.to_ne_bytes());
    }
    // TODO symmetric key to be replaced
    // couldn't figure out how to get 
    let payload = encrypt_payload_symmetric(&mut groups, &secrets::INTERROGATE_KEYS[0].0, &[Opcode::Interrogate as u8]).unwrap();

    // TODO replace with uart1 io. pretend Interrogate_retrieve exists pls
    // TODO, does this solve the above todo
    let request= Message::send_data(Opcode::Interrogate, &payload, MessagePort::UART1).unwrap();

    let mut info = Message::read(MessagePort::UART1).unwrap();

    if info.opcode != Opcode::Interrogate {
        panic!("Incorrect Opcode for Retrieve Interrogate");
    }

    let body = decrypt_payload_symmetric(&mut info.body, &secrets::INTERROGATE_KEYS[1].0, &[Opcode::Interrogate as u8]).unwrap();
    let size_of_metadata: usize = 32 + 2 + 1 + 1;
    // lol hardcoded

    // same as list
    let mut list: [u8; 4 + 1 + NAME_SIZE + 2 + 1] = [0u8; 4 + 1 + NAME_SIZE + 2 + 1]; 
    let mut counter: usize = 0;

    // TODO
    for i in (0..body.len()).step_by(size_of_metadata) {
        crypto::decrypt_payload_pub_combined(&mut body[(i * size_of_metadata)..((i * size_of_metadata) + size_of_metadata)], &secrets::GROUP_KEYS[0].pk_inter.0).unwrap();
        list[4 + (i * size_of_metadata)..4 + size_of_metadata + (i * size_of_metadata)].copy_from_slice(&body[(i * size_of_metadata)..((i * size_of_metadata) + size_of_metadata)]);
        counter += 1;
    }

    list[0] = counter as u8;
    //TODO: is this the correct port
    Message::send_data(Opcode::Interrogate, &list, MessagePort::UART0);

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
    let uart = uart1();
    let opcode = uart.read_byte().unwrap();
    let mut body = [0; 8];
    let _ = uart.read_bytes(&mut body).unwrap();
    listen::recv(ctx, opcode.try_into().unwrap(), &mut body);
}
