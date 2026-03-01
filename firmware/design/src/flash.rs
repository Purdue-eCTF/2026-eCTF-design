use core::marker::PhantomData;

use bytemuck::{NoUninit, Pod, Zeroable};
use mspm0l222x_hal::flash::FLASH_PAGE_SIZE;

// TODO: automatically handle partial page writes
pub const FLASH_MAGIC: u64 = 0x7c79b307cf99d0d6;
pub struct FlashEntry<T: NoUninit> {
    location: u32,
    pages: u32,
    _marker: PhantomData<T>,
}

impl<T: NoUninit> FlashEntry<T> {
    pub unsafe fn new(location: u32) -> Self {
        // Flash entry must be sector-aligned
        assert!(
            location.is_multiple_of(FLASH_PAGE_SIZE as u32),
            "location {} is not page-aligned",
            location
        );
        // Type must be 8-byte aligned
        const {
            assert!(size_of::<T>().is_multiple_of(8));
        }

        Self {
            location,
            pages: (size_of::<T>() + size_of_val(&FLASH_MAGIC)).div_ceil(FLASH_PAGE_SIZE) as u32,
            _marker: PhantomData,
        }
    }

    pub unsafe fn erase(&self) {
        let flash = mspm0l222x_hal::flash::flash();

        // erase page with magic word first so that
        // partially deleted entry is treated as empty
        for page in (0..self.pages).rev() {
            unsafe {
                let _ = flash.erase_page(self.location + page * FLASH_PAGE_SIZE as u32);
            }
        }
    }

    pub unsafe fn set(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        let res = self.set_inner(data);
        if res.is_err() {
            // prevent partial writes
            unsafe { self.erase() };
        }

        res
    }

    pub fn is_set(&self) -> bool {
        (unsafe { *((self.location + size_of::<T>() as u32) as *const u64) }) == FLASH_MAGIC
    }

    #[inline]
    fn set_inner(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        let flash = mspm0l222x_hal::flash::flash();

        let data = bytemuck::bytes_of(data);
        let (words, []): (&[[u8; 8]], _) = data.as_chunks() else {
            unreachable!()
        };

        flash.write_unprotect(self.location, self.pages * FLASH_PAGE_SIZE as u32);
        unsafe { self.erase() };

        let magic_bytes = FLASH_MAGIC.to_le_bytes();
        for (i, word) in words
            .iter()
            // write magic bytes at the end of data
            .chain(core::iter::once(&magic_bytes))
            .enumerate()
        {
            unsafe { flash.write_word(self.location + i as u32 * 8, word)? };
        }

        flash.write_protect(self.location, self.pages * FLASH_PAGE_SIZE as u32);
        Ok(())
    }

    pub fn get(&self) -> Option<&T> {
        if self.is_set() {
            Some(unsafe { &*(self.location as *const T) })
        } else {
            None
        }
    }
}
