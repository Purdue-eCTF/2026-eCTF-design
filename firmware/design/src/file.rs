use core::{fmt, ops::Index};

use bytemuck::{NoUninit, Pod, Zeroable};

use crate::context;

pub const CONTENT_SIZE: usize = 8192;
pub const UUID_SIZE: usize = 16;
pub const NAME_SIZE: usize = 32;
pub const FILE_METADATA_SIZE: usize = size_of::<File>() - CONTENT_SIZE - 6;

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(transparent)]
pub struct FileName(pub [u8; NAME_SIZE]);

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(transparent)]
pub struct UUID(pub [u8; UUID_SIZE]);

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C, packed)]
pub struct FileMeta {
    pub name: FileName,
    pub group: u16,
    pub slot: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProtectedFileData {
    pub nonce: [u8; 24],
    pub tag: [u8; 16],
    pub gn: [u8; 32],
    pub name: FileName,
    pub uuid: UUID,
    pub group: u16,
    pub contents: [u8; CONTENT_SIZE],
    _pad: [u8; 6],
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
            contents: [0; CONTENT_SIZE],
            _pad: [0; 6],
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
pub struct File {
    pub state: u64,
    pub signature: [u8; 64],
    pub protected: ProtectedFileData,
}

impl File {
    pub const EMPTY: u64 = 0xd8b1f12cd454a41d;
    pub const FULL: u64 = 0xc0aa73e0c260426e;
    const fn empty() -> Self {
        Self {
            state: File::EMPTY,
            signature: [0; _],
            protected: ProtectedFileData::empty(),
        }
    }
    pub(crate) fn is_full(&self) -> bool {
        self.state == File::FULL
    }
    pub(crate) fn new() -> Self {
        Self {
            state: File::EMPTY,
            signature: [0; _],
            protected: ProtectedFileData {
                nonce: [0; _],
                tag: [0; _],
                gn: [0; _],
                name: FileName([0; _]),
                uuid: UUID([0; _]),
                group: 0,
                contents: [0; _],
                _pad: [0; _],
            },
        }
    }
}
unsafe impl Zeroable for File {
    fn zeroed() -> Self {
        Self::empty()
    }
}
unsafe impl Pod for File {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FatEntry {
    pub uuid: UUID,
    pub length: u16,
    pub padding: u16,
    pub addr: u32,
}

impl FatEntry {
    const fn empty() -> Self {
        Self {
            uuid: UUID([0; _]),
            length: 0,
            padding: 0,
            addr: 0,
        }
    }
}

impl core::fmt::Debug for FatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FatEntry")
            .field("uuid", &self.uuid)
            .field("length", &self.length)
            .field("addr", &self.addr)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FatTable {
    pub entries: [FatEntry; 8],
}
impl FatTable {
    pub(crate) fn new(entries: [FatEntry; 8]) -> Self {
        Self { entries }
    }
    pub const fn empty() -> Self {
        Self {
            entries: [FatEntry::empty(); 8],
        }
    }
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
