use core::ops::Index;

use bytemuck::{NoUninit, Pod, Zeroable};

use crate::context;

pub const CONTENT_SIZE: usize = 8192;
pub const UUID_SIZE: usize = 16;
pub const NAME_SIZE: usize = 32;

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(transparent)]
pub struct FileName(pub [u8; NAME_SIZE]);

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(transparent)]
pub struct UUID(pub [u8; UUID_SIZE]);

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C, packed)]
pub struct FileMeta {
    pub slot: u8,
    pub group: u16,
    pub name: FileName,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Signed file data. Includes ciphertext, required file metadata, as well as G^n, nonce, and tag for decryption.
pub struct ProtectedFileData {
    pub nonce: [u8; 24],
    pub tag: [u8; 16],
    pub gn: [u8; 32],
    pub name: FileName,
    pub uuid: UUID,
    pub group: u16,
    pub contents_length: u16,
    pub contents: [u8; CONTENT_SIZE],
}

impl ProtectedFileData {
    pub const fn empty() -> Self {
        Self {
            nonce: [0; 24],
            tag: [0; 16],
            gn: [0; 32],
            name: FileName([0; NAME_SIZE]),
            uuid: UUID([0; UUID_SIZE]),
            group: 0,
            contents_length: 0,
            contents: [0; CONTENT_SIZE],
        }
    }
}
unsafe impl Zeroable for ProtectedFileData {
    fn zeroed() -> Self {
        Self::empty()
    }
}
unsafe impl Pod for ProtectedFileData {}
#[repr(C)]
#[derive(Debug, Clone, Copy)]

/// Layout of a file. Includes state(EMPTY or FULL), ed25519 signature, and signed data.
pub struct File {
    pub state: u64,
    pub signature: [u8; 64],
    pub protected: ProtectedFileData,
    _pad: [u8; 4], // pad to a multiple of 8 as required by FlashEntry
}

impl File {
    pub const EMPTY: u64 = 0xd8b1f12cd454a41d;
    pub const FULL: u64 = 0xc0aa73e0c260426e;
    pub const fn empty() -> Self {
        Self {
            state: File::EMPTY,
            signature: [0; _],
            protected: ProtectedFileData::empty(),
            _pad: [u8; 4],
        }
    }
    pub(crate) fn is_full(&self) -> bool {
        self.state == File::FULL
    }
}
unsafe impl Zeroable for File {
    fn zeroed() -> Self {
        Self::empty()
    }
}
unsafe impl Pod for File {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]

/// File allocation table entry used by the eCTF bootloader.
pub struct FatEntry {
    pub uuid: UUID,
    pub length: u16,
    pub padding: u16,
    pub addr: u32,
}

#[derive(Debug, Clone, Copy)]

/// File allocation table used by the eCTF bootloader.
pub struct FatTable {
    pub entries: [FatEntry; 8],
}

impl Index<usize> for FatTable {
    type Output = FatEntry;
    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}
unsafe impl NoUninit for FatTable {}

#[repr(align(1024), C)]
#[derive(Copy, Clone)]
pub struct FileSlot {
    pub file: File,
    pub magic: u64,
}

// Force "filled" files and FAT to appear in flash on first boot
#[unsafe(link_section = ".files.default")]
#[unsafe(no_mangle)]
pub static __FILES: [FileSlot; 8] = [FileSlot {
    file: File::empty(),
    magic: context::FLASH_MAGIC,
}; 8];

#[unsafe(link_section = ".filetable.default")]
#[unsafe(no_mangle)]
pub static __FAT: ([u8; core::mem::size_of::<FatTable>()], u64) = ([0; _], context::FLASH_MAGIC);
