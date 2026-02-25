use core::marker::PhantomData;

use bytemuck::{NoUninit, Pod, Zeroable};
use mspm0l222x_hal::flash::FLASH_PAGE_SIZE;

pub const COMMIT_MAGIC: u16 = 0x3340;

unsafe extern "C" {
    pub static _commit: u8;
}

fn write_commit(commit: Commit) {
    let flash = mspm0l222x_hal::flash::flash();
    let commits: &[Commit; 128] = unsafe { &*(&raw const _commit as *const [Commit; 128]) };
    let commits_location = &raw const *commits as u32;

    // find first empty commit entry
    match commits.iter().position(|c| c.magic != COMMIT_MAGIC) {
        None => {
            // erase page and write at index 0
            unsafe { flash.erase_page(commits_location).unwrap() };
            unsafe {
                flash
                    .write_word(commits_location, bytemuck::cast_ref(&commit))
                    .unwrap()
            };
        }
        Some(i) => unsafe {
            flash
                .write_word(commits_location + 8 * i as u32, bytemuck::cast_ref(&commit))
                .unwrap()
        },
    }
}

// TODO: verify each pair is write/erase, then end
pub(crate) fn check_commits() {
    let flash = mspm0l222x_hal::flash::flash();
    let commits: &[Commit; 128] = unsafe { &*(&raw const _commit as *const [Commit; 128]) };
    let commits_location = &raw const *commits as u32;

    let end = commits
        .iter()
        .position(|c| c.magic != COMMIT_MAGIC)
        .unwrap_or(128);

    if end % 2 != 0 {
        // finish or revert last operation
        let last = commits[end - 1];
        for page in 0..last.pages {
            unsafe {
                flash
                    .erase_page(last.location + FLASH_PAGE_SIZE as u32 * page as u32)
                    .unwrap()
            };
        }
    }
    unsafe { flash.erase_page(commits_location).unwrap() };
}

#[repr(u8)]
enum CommitType {
    End = 1,
    Write = 2,
    Erase = 3,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Commit {
    location: u32,
    pages: u8,
    typ: u8,
    magic: u16,
}
impl Commit {
    fn new(typ: u8, pages: u8, location: u32) -> Self {
        Self {
            typ,
            pages,
            location,
            magic: COMMIT_MAGIC,
        }
    }
}

impl TryFrom<[u8; 8]> for Commit {
    type Error = ();

    fn try_from(value: [u8; 8]) -> Result<Self, Self::Error> {
        let commit: &Commit = bytemuck::cast_ref(&value);
        // we know that the largest flash op is erasing + writing a 9-page file
        if (!(1..=3).contains(&commit.typ)) || commit.magic != COMMIT_MAGIC || commit.pages > 9 {
            return Err(());
        }
        Ok(*commit)
    }
}

// TODO: automatically handle partial page writes
pub const FLASH_MAGIC: u64 = 0x7c79b307cf99d0d6;

/// Location in flash and number of pages.
pub struct FlashEntry<T: NoUninit> {
    location: u32,
    pages: u32,
    _marker: PhantomData<T>,
}

impl<T: NoUninit> FlashEntry<T> {
    /// Create a new flash entry at a specified location and return it
    pub(crate) unsafe fn new(location: u32) -> Self {
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

    /// Erase everything in contained flash entry
    pub(crate) unsafe fn erase(&self) {
        write_commit(Commit::new(
            CommitType::Erase as u8,
            self.pages as u8,
            self.location,
        ));

        let flash = mspm0l222x_hal::flash::flash();
        for page in 0..self.pages {
            unsafe {
                let _ = flash.erase_page(self.location + page * FLASH_PAGE_SIZE as u32);
            }
        }

        write_commit(Commit::new(
            CommitType::End as u8,
            self.pages as u8,
            self.location,
        ));
    }

    /// Write contents into flash entry, erasing it on error
    pub(crate) unsafe fn set(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        let res = self.set_inner(data);
        if res.is_err() {
            // prevent partial writes
            unsafe { self.erase() };
        }

        res
    }

    /// Check if there is content in the flash entry
    pub(crate) fn is_set(&self) -> bool {
        (unsafe { *((self.location + size_of::<T>() as u32) as *const u64) }) == FLASH_MAGIC
    }

    /// Write words into flash entry
    #[inline]
    fn set_inner(&self, data: &T) -> Result<(), mspm0l222x_hal::HalError> {
        write_commit(Commit::new(
            CommitType::Write as u8,
            self.pages as u8,
            self.location,
        ));

        let flash = mspm0l222x_hal::flash::flash();

        let data = bytemuck::bytes_of(data);
        let (words, []): (&[[u8; 8]], _) = data.as_chunks() else {
            unreachable!()
        };

        // reset all pages before writing
        flash.write_unprotect(self.location, self.pages * FLASH_PAGE_SIZE as u32);
        for page in 0..self.pages {
            unsafe {
                flash.erase_page(self.location + page * FLASH_PAGE_SIZE as u32)?;
            }
        }

        flash.write_unprotect(self.location, self.pages * FLASH_PAGE_SIZE as u32);

        // Write data by chunks into pages
        let magic_bytes = FLASH_MAGIC.to_le_bytes();
        for (i, word) in words
            .iter()
            // write magic bytes at the end of data
            .chain(core::iter::once(&magic_bytes))
            .enumerate()
        {
            unsafe { flash.write_word(self.location + i as u32 * 8, word)? };
        }

        write_commit(Commit::new(
            CommitType::Write as u8,
            self.pages as u8,
            self.location,
        ));
        Ok(())
    }

    /// Safely retrieve data from a flash entry if it exists
    pub(crate) fn get(&self) -> Option<&T> {
        if self.is_set() {
            Some(unsafe { &*(self.location as *const T) })
        } else {
            None
        }
    }
}
