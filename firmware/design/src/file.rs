use core::ops::Index;

use bytemuck::{NoUninit, Pod, Zeroable};

use crate::{crypto::SymmetricMetadata, flash, protocol::ProtocolError, secrets};

pub const CONTENT_SIZE: usize = 8192;
pub const UUID_SIZE: usize = 16;
pub const NAME_SIZE: usize = 32;

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(transparent)]
pub struct FileName(pub [u8; NAME_SIZE]);

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(transparent)]
pub struct UUID(pub [u8; UUID_SIZE]);

#[derive(Debug, Copy, Clone)]
pub struct FileContents(pub [u8; CONTENT_SIZE]);

// pod macro does not support [u8; 8192], so manually implement
unsafe impl Pod for FileContents {}
unsafe impl Zeroable for FileContents {
    fn zeroed() -> Self {
        FileContents([0; _])
    }
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C, packed)]
pub struct FileMeta {
    pub slot: u8,
    pub group: u16,
    pub name: FileName,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct ProtectedFileData {
    pub nonce: [u8; 24],
    pub tag: [u8; 16],
    pub gn: [u8; 32],
    pub name: FileName,
    pub uuid: UUID,
    pub uuid_ct_metadata: SymmetricMetadata,
    pub group: u16,
    pub contents_length: u16,
    pub contents: FileContents,
}

impl ProtectedFileData {
    pub const fn empty() -> Self {
        Self {
            nonce: [0; 24],
            tag: [0; 16],
            gn: [0; 32],
            name: FileName([0; NAME_SIZE]),
            uuid: UUID([0; UUID_SIZE]),
            uuid_ct_metadata: SymmetricMetadata::empty(),
            group: 0,
            contents_length: 0,
            contents: FileContents([0; _]),
        }
    }

    pub fn associated_data(&self) -> [u8; NAME_SIZE + 2] {
        let mut ad = [0u8; NAME_SIZE + 2];
        ad[..NAME_SIZE].copy_from_slice(&self.name.0);
        ad[NAME_SIZE..].copy_from_slice(&self.group.to_le_bytes());
        ad
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct File {
    pub state: u64,
    pub signature: [u8; 64],
    pub protected: ProtectedFileData,
    _padding: [u8; 4],
}

impl File {
    pub const EMPTY: u64 = 0xd8b1f12cd454a41d;
    pub const FULL: u64 = 0xc0aa73e0c260426e;
    pub const fn empty() -> Self {
        Self {
            state: File::EMPTY,
            signature: [0; _],
            protected: ProtectedFileData::empty(),
            _padding: [0; _],
        }
    }
    pub(crate) fn is_full(&self) -> bool {
        self.state == File::FULL
    }

    pub(crate) fn to_fat(&self, k_auth: &[u8; 32]) -> Result<FatEntry, ProtocolError> {
        if !self.is_full() {
            return Ok(FatEntry::empty());
        }

        let enc_group_keys = secrets::get_enc_group_keys(self.protected.group)?;
        let group_keys = enc_group_keys.decrypt(k_auth);

        let mut uuid = self.protected.uuid;
        let ad = self.protected.associated_data();
        self.protected.uuid_ct_metadata.decrypt(
            bytemuck::bytes_of_mut(&mut uuid),
            &group_keys.k_uuid.ok_or(ProtocolError::InvalidGroup)?.0,
            &ad,
        )?;

        Ok(FatEntry {
            uuid,
            length: self.protected.contents_length,
            padding: 0,
            addr: &raw const self.protected.contents as u32,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FatEntry {
    pub uuid: UUID,
    pub length: u16,
    pub padding: u16,
    pub addr: u32,
}

impl FatEntry {
    pub(crate) const fn empty() -> Self {
        Self {
            uuid: UUID([0; _]),
            length: 0,
            padding: 0,
            addr: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
// first 6 files fit after end of app1
#[unsafe(link_section = ".files_app1.default")]
#[unsafe(no_mangle)]
pub static __FILES_APP1: [FileSlot; 6] = [FileSlot {
    file: File::empty(),
    magic: flash::FLASH_MAGIC,
}; 6];

// last 2 files go after file table before app2
#[unsafe(link_section = ".files_app2.default")]
#[unsafe(no_mangle)]
pub static __FILES_APP2: [FileSlot; 2] = [FileSlot {
    file: File::empty(),
    magic: flash::FLASH_MAGIC,
}; 2];

#[unsafe(link_section = ".filetable.default")]
#[unsafe(no_mangle)]
pub static __FAT: ([u8; core::mem::size_of::<FatTable>()], u64) = ([0; _], flash::FLASH_MAGIC);
