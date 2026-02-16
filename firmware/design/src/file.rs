use core::{fmt, ops::Index};

use bytemuck::NoUninit;

use crate::util;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct File {
    pub contents: [u8; 8192],
    pub signature: [u8; 32],
    pub nonce: [u8; 32],
    pub state: u64,
}

impl File {
    pub const EMPTY: u64 = 0xd8b1f12cd454a41d;
    pub const FULL: u64 = 0xc0aa73e0c260426e;
    const fn empty() -> Self {
        Self {
            contents: [0xff; _],
            signature: [0; _],
            state: File::EMPTY,
            nonce: [0; _],
        }
    }
    pub(crate) fn is_full(&self) -> bool {
        self.state == File::FULL
    }
}
unsafe impl NoUninit for File {} // Generic arrays not supported by derive macro

#[unsafe(link_section = ".files.default")]
#[unsafe(no_mangle)]
pub static __FILES: [(File, u64, [u8; (9 * 1024) - size_of::<File>() - 8]); 8] = [
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
    (File::empty(), util::FLASH_MAGIC, [0; _]),
];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FatEntry {
    pub uuid: [u8; 16],
    pub length: u16,
    pub padding: u16,
    pub addr: u32,
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
}

impl Index<usize> for FatTable {
    type Output = FatEntry;
    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}
unsafe impl NoUninit for FatTable {}
