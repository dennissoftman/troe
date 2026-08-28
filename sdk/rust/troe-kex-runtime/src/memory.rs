//! POSIX-shaped private anonymous memory over the typed KEX capability.
//!
//! These helpers deliberately exclude shared, file-backed, fixed-address, and
//! executable mappings. They do not manufacture authority: callers must pass
//! the [`PrivateMemory`] capability granted in their KEX manifest.

use core::{ptr::NonNull, slice};
use troe_kex_sdk::{Error as KexError, PrivateMemory, private_memory};

const PAGE_BYTES: u64 = 4096;

/// Pages are inaccessible.
pub const PROT_NONE: i32 = 0;
/// Pages may be read.
pub const PROT_READ: i32 = 1;
/// Pages may be written. TROE requires readable writable data mappings.
pub const PROT_WRITE: i32 = 2;
/// Executable anonymous memory is not part of the private-data capability.
pub const PROT_EXEC: i32 = 4;
/// Create a process-private mapping.
pub const MAP_PRIVATE: i32 = 2;
/// Ignore a file descriptor and create zeroed anonymous pages.
pub const MAP_ANONYMOUS: i32 = 0x20;
/// Compatibility spelling used by some POSIX software.
pub const MAP_ANON: i32 = MAP_ANONYMOUS;
/// Fixed placement is intentionally unsupported; hints remain advisory.
pub const MAP_FIXED: i32 = 0x10;

/// Private-memory compatibility failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid length, alignment, flag, protection, or address geometry.
    InvalidArgument,
    /// Shared, file-backed, fixed-address, or executable memory was requested.
    Unsupported,
    /// The typed KEX service rejected or failed the operation.
    Service(KexError),
}

impl From<KexError> for Error {
    fn from(error: KexError) -> Self {
        Self::Service(error)
    }
}

/// One owned anonymous mapping that unmaps itself on drop.
pub struct AnonymousMapping {
    memory: PrivateMemory,
    address: NonNull<u8>,
    byte_len: u64,
    page_count: u64,
    protection: i32,
}

impl AnonymousMapping {
    /// Map a zeroed process-private range.
    ///
    /// `address_hint` is advisory and may be zero. `flags` must be exactly the
    /// private-anonymous profile; fixed placement is rejected.
    ///
    /// # Errors
    ///
    /// Reports invalid geometry/profile, missing resources, configured limits,
    /// or typed call-gate failure.
    pub fn map(
        mut memory: PrivateMemory,
        address_hint: u64,
        byte_len: u64,
        protection: i32,
        flags: i32,
    ) -> Result<Self, Error> {
        if byte_len == 0 || !address_hint.is_multiple_of(PAGE_BYTES) {
            return Err(Error::InvalidArgument);
        }
        if flags != MAP_PRIVATE | MAP_ANONYMOUS || flags & MAP_FIXED != 0 {
            return Err(Error::Unsupported);
        }
        let typed = typed_protection(protection)?;
        let page_count = byte_len
            .checked_add(PAGE_BYTES - 1)
            .ok_or(Error::InvalidArgument)?
            / PAGE_BYTES;
        let address = memory.map_zeroed(page_count, 1, address_hint, typed)?;
        let address = usize::try_from(address).map_err(|_| Error::InvalidArgument)?;
        let address = NonNull::new(address as *mut u8).ok_or(Error::InvalidArgument)?;
        Ok(Self {
            memory,
            address,
            byte_len,
            page_count,
            protection,
        })
    }

    /// First byte of the mapping.
    #[must_use]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.address.as_ptr()
    }

    /// Caller-requested byte length (the committed mapping is page-rounded).
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.byte_len
    }

    /// Whether the caller-requested byte span is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Current compatibility protection bits.
    #[must_use]
    pub const fn protection(&self) -> i32 {
        self.protection
    }

    /// Change access over the complete mapping.
    ///
    /// # Errors
    ///
    /// Reports unsupported executable/write-only access or a typed service
    /// failure. Contents survive `PROT_NONE` and become visible again later.
    pub fn protect(&mut self, protection: i32) -> Result<(), Error> {
        let typed = typed_protection(protection)?;
        self.memory.protect(
            u64::try_from(self.address.as_ptr() as usize).map_err(|_| Error::InvalidArgument)?,
            self.page_count,
            typed,
        )?;
        self.protection = protection;
        Ok(())
    }

    /// View the caller-requested span when it is readable.
    ///
    /// # Safety
    ///
    /// No aliasing mutable reference may exist, and the caller must not retain
    /// the slice across protection changes or unmapping.
    ///
    /// # Errors
    ///
    /// Reports that the mapping is not readable or its length cannot be
    /// represented by the target pointer width.
    pub unsafe fn as_slice(&self) -> Result<&[u8], Error> {
        if self.protection & PROT_READ == 0 {
            return Err(Error::InvalidArgument);
        }
        let length = usize::try_from(self.byte_len).map_err(|_| Error::InvalidArgument)?;
        // SAFETY: The owned mapping covers the page-rounded requested span;
        // readable access and aliasing are required by this method's contract.
        Ok(unsafe { slice::from_raw_parts(self.address.as_ptr(), length) })
    }

    /// View the caller-requested span when it is writable.
    ///
    /// # Safety
    ///
    /// This mapping must have unique access and the returned slice must not be
    /// retained across protection changes or unmapping.
    ///
    /// # Errors
    ///
    /// Reports that the mapping is not writable or its length cannot be
    /// represented by the target pointer width.
    pub unsafe fn as_mut_slice(&mut self) -> Result<&mut [u8], Error> {
        if self.protection & PROT_WRITE == 0 {
            return Err(Error::InvalidArgument);
        }
        let length = usize::try_from(self.byte_len).map_err(|_| Error::InvalidArgument)?;
        // SAFETY: The owned mapping covers the page-rounded requested span;
        // writable access and uniqueness are required by this method's contract.
        Ok(unsafe { slice::from_raw_parts_mut(self.address.as_ptr(), length) })
    }

    /// Explicitly unmap, returning a typed failure instead of ignoring it in
    /// [`Drop`].
    ///
    /// # Errors
    ///
    /// Reports a typed call-gate or kernel mapping failure.
    pub fn unmap(mut self) -> Result<(), Error> {
        let result = self.memory.unmap(
            u64::try_from(self.address.as_ptr() as usize).map_err(|_| Error::InvalidArgument)?,
            self.page_count,
        );
        if result.is_ok() {
            self.page_count = 0;
        }
        result.map_err(Into::into)
    }
}

impl Drop for AnonymousMapping {
    fn drop(&mut self) {
        if self.page_count != 0 {
            let _ignored = self.memory.unmap(
                u64::try_from(self.address.as_ptr() as usize).unwrap_or(0),
                self.page_count,
            );
        }
    }
}

fn typed_protection(value: i32) -> Result<private_memory::Protection, Error> {
    if value & PROT_EXEC != 0 {
        return Err(Error::Unsupported);
    }
    match value {
        PROT_NONE => Ok(private_memory::Protection::None),
        PROT_READ => Ok(private_memory::Protection::Read),
        value if value == PROT_READ | PROT_WRITE => Ok(private_memory::Protection::ReadWrite),
        _ => Err(Error::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Error, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE,
        typed_protection,
    };
    use troe_kex_sdk::private_memory::Protection;

    #[test]
    fn protection_profile_is_explicit_and_non_executable() {
        assert_eq!(typed_protection(PROT_NONE), Ok(Protection::None));
        assert_eq!(typed_protection(PROT_READ), Ok(Protection::Read));
        assert_eq!(
            typed_protection(PROT_READ | PROT_WRITE),
            Ok(Protection::ReadWrite)
        );
        assert_eq!(typed_protection(PROT_WRITE), Err(Error::InvalidArgument));
        assert_eq!(
            typed_protection(PROT_READ | PROT_EXEC),
            Err(Error::Unsupported)
        );
        assert_eq!(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0x32);
    }
}
