const NAME_SIZE: usize = 32;
const UUID_SIZE: usize = 16;
const MAX_FILE_SIZE: usize = 8192;
const SIGNATURE_SIZE: usize = 32;

#[derive(Debug)]
pub enum FileViewError {
    BufferTooSmall,
}

#[derive(Default)]
pub struct ConcatOffsets {
    pub name: usize,
    pub group: usize,
    pub uuid: usize,
    pub data: usize,
    pub end: usize,
}

pub struct FileView<'a> {
    name: &'a [u8; NAME_SIZE],
    group: u16,
    uuid: &'a [u8; UUID_SIZE],
    data: &'a [u8],
}

impl<'a> FileView<'a> {
    pub fn new(
        name: &'a [u8; NAME_SIZE],
        group: u16,
        uuid: &'a [u8; UUID_SIZE],
        data: &'a [u8],
    ) -> Self {
        Self {
            name,
            group,
            uuid,
            data,
        }
    }

    pub fn concat_bytes(&self, buf: &mut [u8]) -> Result<ConcatOffsets, FileViewError> {
        let capacity = self.calculate_concat_size();
        if buf.len() < capacity {
            return Err(FileViewError::BufferTooSmall);
        }
        let mut i = 0;
        let mut o = ConcatOffsets::default();

        buf[i..i + NAME_SIZE].copy_from_slice(self.name);
        o.name = 0;
        i += NAME_SIZE;

        buf[i..i + 2].copy_from_slice(&self.group.to_le_bytes());
        o.group = i;
        i += 2;

        buf[i..i + UUID_SIZE].copy_from_slice(self.uuid);
        o.uuid = i;
        i += UUID_SIZE;

        buf[i..i + self.data.len()].copy_from_slice(self.data);
        i += self.data.len();
        o.end = i;
        Ok(o)
    }

    fn calculate_concat_size(&self) -> usize {
        NAME_SIZE + 2 + UUID_SIZE + self.data.len()
    }
}
