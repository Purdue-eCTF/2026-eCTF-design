pub const NAME_SIZE: usize = 32;
pub const UUID_SIZE: usize = 16;
pub const MAX_FILE_SIZE: usize = 8192;
pub const SIGNATURE_SIZE: usize = 64;

// TODO: Unsure if MAX_FILE_SIZE is actually the max because file is stored as
// GN || ct which is why I'm adding 128 to be safe

pub const MAX_VIEW_SIZE: usize = NAME_SIZE + 2 + 2 + MAX_FILE_SIZE + SIGNATURE_SIZE + 128;

#[derive(Debug)]
pub enum ConcatError {
    BadOffsets,
    BufferTooSmall,
}

pub struct ConcatView<'a> {
    pub signature: &'a mut [u8; SIGNATURE_SIZE],
    pub name: &'a mut [u8],
    pub group: &'a mut [u8; 2],
    pub uuid: &'a mut [u8; UUID_SIZE],
    pub data: &'a mut [u8],
}

impl<'a> ConcatView<'a> {
    pub fn new(offsets: &ConcatOffsets, underlying: &'a mut [u8]) -> Result<Self, ConcatError> {
        let sig_l = offsets.name - offsets.signature;
        let name_l = offsets.group - offsets.name;
        let group_l = offsets.uuid - offsets.group;
        let uuid_l = offsets.data - offsets.uuid;
        let data_l = offsets.end - offsets.data;
        let total = sig_l + name_l + group_l + uuid_l + data_l;

        if (sig_l != SIGNATURE_SIZE)
            || (name_l <= 0)
            || (group_l != 2)
            || (uuid_l != 16)
            || (data_l <= 0)
            || (offsets.end - offsets.signature != total)
        {
            return Err(ConcatError::BadOffsets);
        }

        if total > underlying.len() {
            return Err(ConcatError::BufferTooSmall);
        }

        let (signature, rest) = underlying.split_at_mut(sig_l);
        let (name, rest) = rest.split_at_mut(name_l);
        let (group, rest) = rest.split_at_mut(2);
        let (uuid, rest) = rest.split_at_mut(16);
        let (data, _) = rest.split_at_mut(data_l);
        Ok(Self {
            signature: signature.try_into().unwrap(),
            name,
            group: group.try_into().unwrap(),
            uuid: uuid.try_into().unwrap(),
            data,
        })
    }

    // TODO: check UUID is good, name is good, groups are good...
    pub fn validate(&self) -> Result<(), ConcatError> {
        todo!()
    }
}

#[derive(Default)]
pub struct ConcatOffsets {
    pub signature: usize,
    pub name: usize,
    pub group: usize,
    pub uuid: usize,
    pub data: usize,
    pub end: usize,
}

pub struct FileView<'a> {
    pub signature: &'a [u8; SIGNATURE_SIZE],
    pub name: &'a [u8; NAME_SIZE],
    pub group: u16,
    pub uuid: &'a [u8; UUID_SIZE],
    pub data: &'a [u8],
    pub exists: bool,
}

//represents concatenated date
pub struct Concat<'a> {
    offsets: ConcatOffsets,
    buf: &'a mut [u8],
}

impl<'a> Concat<'a> {
    pub fn as_view<'b>(&'b mut self) -> Result<ConcatView<'b>, ConcatError> {
        Ok(ConcatView::new(&self.offsets, self.buf)?)
    }

    // TODO this should only include name..end
    pub fn get_buf(&mut self) -> &mut [u8] {
        self.buf
    }

    pub fn validate(&mut self) -> Result<(), ConcatError> {
        let view = self.as_view()?;
        view.validate()?;
        Ok(())
    }

    pub fn new(offsets: ConcatOffsets, data: &'a mut [u8]) -> Result<Self, ConcatError> {
        let mut s = Self { offsets, buf: data };
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
        let (group_bytes, rest) = rest.split_at(2);
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

    pub fn concat_bytes<'b>(&self, buf: &'b mut [u8]) -> Result<Concat<'b>, ConcatError> {
        let capacity = self.calculate_concat_size();
        if buf.len() < capacity {
            return Err(ConcatError::BufferTooSmall);
        }
        let mut i = 0;
        let mut o = ConcatOffsets::default();

        buf[i..i + SIGNATURE_SIZE].copy_from_slice(self.signature);
        o.signature = i;
        i += SIGNATURE_SIZE;

        buf[i..i + NAME_SIZE].copy_from_slice(self.name);
        o.name = i;
        i += NAME_SIZE;

        buf[i..i + 2].copy_from_slice(&self.group.to_le_bytes());
        o.group = i;
        i += 2;

        buf[i..i + UUID_SIZE].copy_from_slice(self.uuid);
        o.uuid = i;
        i += UUID_SIZE;

        o.data = i;
        buf[i..i + self.data.len()].copy_from_slice(self.data);
        i += self.data.len();
        o.end = i;
        let r = Concat::new(o, buf)?;
        
        Ok(r)
    }

    fn calculate_concat_size(&self) -> usize {
        SIGNATURE_SIZE + NAME_SIZE + 2 + UUID_SIZE + self.data.len()
    }
}
