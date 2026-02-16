pub const NAME_SIZE: usize = 32;
pub const UUID_SIZE: usize = 16;
pub const MAX_FILE_SIZE: usize = 8192;
pub const SIGNATURE_SIZE: usize = 32;

// TODO: Unsure if MAX_FILE_SIZE is actually the max because file is stored as
// GN || ct which is why I'm adding 128 to be safe

pub const MAX_VIEW_SIZE: usize = NAME_SIZE + 2 + 2 + MAX_FILE_SIZE + SIGNATURE_SIZE + 128;

#[derive(Debug)]
pub enum ConcatError {
    BadOffsets,
    BufferTooSmall,
}

pub struct ConcatView<'a> {
    pub name: &'a mut [u8],
    pub group: &'a mut [u8; 2],
    pub uuid: &'a mut [u8; 16],
    pub data: &'a mut [u8],
}

impl<'a> ConcatView<'a> {
    pub fn new(offsets: &ConcatOffsets, underlying: &'a mut [u8]) -> Result<Self, ConcatError> {
        let name_l = offsets.group - offsets.name;
        let group_l = offsets.uuid - offsets.group;
        let uuid_l = offsets.data - offsets.uuid;
        let data_l = offsets.end - offsets.data;
        let total = name_l + group_l + uuid_l + data_l;

        if (name_l <= 0)
            || (group_l != 2)
            || (uuid_l != 16)
            || (data_l <= 0)
            || (offsets.end - offsets.name != total)
        {
            return Err(ConcatError::BadOffsets);
        }

        if total > underlying.len() {
            return Err(ConcatError::BufferTooSmall);
        }

        let (name, rest) = underlying.split_at_mut(name_l);
        let (group, rest) = rest.split_at_mut(2);
        let (uuid, rest) = rest.split_at_mut(16);
        let (data, _) = rest.split_at_mut(data_l);
        Ok(Self {
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

    pub fn concat_bytes<'b>(&self, buf: &'b mut [u8]) -> Result<Concat<'b>, ConcatError> {
        let capacity = self.calculate_concat_size();
        if buf.len() < capacity {
            return Err(ConcatError::BufferTooSmall);
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
        let r = Concat::new(o, buf)?;
        Ok(r)
    }

    fn calculate_concat_size(&self) -> usize {
        NAME_SIZE + 2 + UUID_SIZE + self.data.len()
    }
}
