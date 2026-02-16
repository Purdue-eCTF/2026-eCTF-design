pub const NAME_SIZE: usize = 32;
pub const GID_SIZE: usize = 2;
pub const UUID_SIZE: usize = 16;
pub const MAX_FILE_SIZE: usize = 8192;
pub const SIGNATURE_SIZE: usize = 64;
pub const MAX_CONTENT_SIZE: usize = MAX_FILE_SIZE - SIGNATURE_SIZE - NAME_SIZE - GID_SIZE - UUID_SIZE - 1;

// TODO: Unsure if MAX_FILE_SIZE is actually the max because file is stored as
// GN || ct which is why I'm adding 128 to be safe

// pub const MAX_VIEW_SIZE: usize = NAME_SIZE + GID_SIZE + 2 + MAX_FILE_SIZE + SIGNATURE_SIZE + 128;

pub const NAME_OFFSET: usize = SIGNATURE_SIZE;
pub const DATA_OFFSET: usize = NAME_OFFSET + NAME_SIZE + GID_SIZE + UUID_SIZE;

#[derive(Debug)]
pub enum ConcatError {
    BadOffsets,
    BufferTooSmall,
}

pub struct MutFileView<'a> {
    pub signature: &'a mut [u8; SIGNATURE_SIZE],
    pub name: &'a mut [u8; NAME_SIZE],
    pub group: &'a mut [u8; 2],
    pub uuid: &'a mut [u8; UUID_SIZE],
    pub data: &'a mut [u8],
}

impl<'a> MutFileView<'a> {
    pub fn new(underlying: &'a mut [u8]) -> Result<Self, ConcatError> {
        let (signature, rest) = underlying.split_at_mut(SIGNATURE_SIZE);
        let (name, rest) = rest.split_at_mut(NAME_SIZE);
        let (group, rest) = rest.split_at_mut(GID_SIZE);
        let (uuid, rest) = rest.split_at_mut(UUID_SIZE);
        Ok(Self {
            signature: signature.try_into().unwrap(),
            name: name.try_into().unwrap(),
            group: group.try_into().unwrap(),
            uuid: uuid.try_into().unwrap(),
            data: rest,
        })
    }

    // TODO: check UUID is good, name is good, groups are good...
    pub fn validate(&self) -> Result<(), ConcatError> {
        todo!()
    }
}

#[repr(C)]
pub struct FileView<'a> {
    pub signature: &'a [u8; SIGNATURE_SIZE],
    pub name: &'a [u8; NAME_SIZE],
    pub group: u16,
    pub uuid: &'a [u8; UUID_SIZE],
    pub data: &'a [u8],
    pub exists: bool,
}

// represents concatenated date
// Signature || N || G || U || data
//
// TODO: If we fix name at 32 bytes padded by null and have data always occupy some
// maximum filesize padded by null bytes we could just use a struct instead of using
// a bunch of slices

pub struct MutFile<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutFile<'a> {
    pub fn as_view<'b>(&'b mut self) -> Result<MutFileView<'b>, ConcatError> {
        Ok(MutFileView::new(self.buf)?)
    }

    pub fn get_buf(&mut self) -> &mut [u8] {
        &mut self.buf[NAME_OFFSET..DATA_OFFSET]
    }

    pub fn validate(&mut self) -> Result<(), ConcatError> {
        let view = self.as_view()?;
        view.validate()?;
        Ok(())
    }

    pub fn new(data: &'a mut [u8]) -> Result<Self, ConcatError> {
        let mut s = Self { buf: data };
        s.validate()?;
        Ok(s)
    }
}

impl<'a> FileView<'a> {
    pub fn new(
        signature: &'a [u8; SIGNATURE_SIZE],
        name: &'a [u8; NAME_SIZE],
        group: u16,
        uuid: &'a [u8; UUID_SIZE],
        data: &'a [u8],
        exists: bool,
    ) -> Self {
        Self {
            signature,
            name,
            group,
            uuid,
            data,
            exists,
        }
    }

    pub fn from_file(file: &'a [u8; MAX_FILE_SIZE], data_size: usize) -> Self {
        let (signature, rest) = file.split_at(SIGNATURE_SIZE);
        let (name, rest) = rest.split_at(NAME_SIZE);
        let (group_bytes, rest) = rest.split_at(GID_SIZE);
        let (uuid, rest) = rest.split_at(UUID_SIZE);
        let (data, exists_byte) = rest.split_at(rest.len() - 1);

        let group = u16::from_le_bytes([group_bytes[0], group_bytes[1]]);
        let exists = exists_byte[0] == 1;

        let data = &data[..data_size];

        Self::new(
            signature.try_into().unwrap(),
            name.try_into().unwrap(),
            group,
            uuid.try_into().unwrap(),
            data,
            exists,
        )
    }

    pub fn copy_to_buf<'b>(&self, buf: &'b mut [u8]) -> Result<MutFile<'b>, ConcatError> {
        if buf.len() < MAX_FILE_SIZE {
            return Err(ConcatError::BufferTooSmall);
        }
        let mut i = 0;

        // TODO: bytemuck this

        buf[i..i + SIGNATURE_SIZE].copy_from_slice(self.signature);
        i += SIGNATURE_SIZE;

        buf[i..i + NAME_SIZE].copy_from_slice(self.name);
        i += NAME_SIZE;

        buf[i..i + GID_SIZE].copy_from_slice(&self.group.to_le_bytes());
        i += GID_SIZE;

        buf[i..i + UUID_SIZE].copy_from_slice(self.uuid);
        i += UUID_SIZE;

        buf[i..MAX_FILE_SIZE - 1].copy_from_slice(self.data);

        buf[MAX_FILE_SIZE - 1] = self.exists as u8;

        Ok(MutFile::new(buf)?)
    }
}
