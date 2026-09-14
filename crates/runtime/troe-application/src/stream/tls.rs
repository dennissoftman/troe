//! Coherent static-TLS source/suffix verification without retaining the image.

use super::{ParsedStreamPrefix, StreamError, StreamedKexPackage, hash_overlap, read_stream_exact};
use crate::{PAGE_BYTES, sha256::Sha256, tls_artifact::Error};

pub(super) struct TlsHashes {
    source: (usize, usize),
    suffix: (usize, usize),
    source_hash: Sha256,
    suffix_hash: Sha256,
}

impl TlsHashes {
    pub(super) fn new(parsed: &ParsedStreamPrefix) -> Result<Self, StreamError> {
        let mut result = Self {
            source: (0, 0),
            suffix: (0, 0),
            source_hash: Sha256::new(),
            suffix_hash: Sha256::new(),
        };
        if let Some(tls) = parsed.executable.tls.filter(|tls| tls.file_bytes != 0) {
            let source_end = tls.source_offset + tls.file_bytes;
            let source = parsed
                .executable
                .segments()
                .find(|segment| {
                    !segment.permissions().executable()
                        && segment.image_offset() <= tls.source_offset
                        && source_end - segment.image_offset() <= segment.file_byte_count()
                })
                .ok_or(StreamError::Tls(Error::InconsistentTemplate))?;
            let source_offset = source
                .file_offset()
                .checked_add(tls.source_offset - source.image_offset())
                .ok_or(StreamError::InvalidLength)?;
            let bounds = |offset: u64| -> Result<(usize, usize), StreamError> {
                let start = parsed
                    .executable_offset
                    .checked_add(offset)
                    .ok_or(StreamError::InvalidLength)?;
                let end = start
                    .checked_add(tls.file_bytes)
                    .ok_or(StreamError::InvalidLength)?;
                Ok((
                    usize::try_from(start).map_err(|_| StreamError::InvalidLength)?,
                    usize::try_from(end).map_err(|_| StreamError::InvalidLength)?,
                ))
            };
            result.source = bounds(source_offset)?;
            result.suffix = bounds(tls.file_offset)?;
        }
        Ok(result)
    }

    pub(super) fn update(&mut self, offset: usize, bytes: &[u8]) {
        hash_overlap(
            &mut self.source_hash,
            offset,
            bytes,
            self.source.0,
            self.source.1,
        );
        hash_overlap(
            &mut self.suffix_hash,
            offset,
            bytes,
            self.suffix.0,
            self.suffix.1,
        );
    }

    pub(super) fn finish(self) -> Result<(), StreamError> {
        if self.source_hash.finish() != self.suffix_hash.finish() {
            return Err(StreamError::Tls(Error::InconsistentTemplate));
        }
        Ok(())
    }
}

/// Copy a verified package's exact immutable initializer with bounded scratch space.
///
/// The destination is provisional until the complete package fingerprint matches.
/// No running image or unverified callback supplies the retained initializer.
/// The caller owns and charges destination capacity before this synchronous copy.
///
/// # Errors
/// Rejects non-TLS packages or a wrong destination size before writes. Read or
/// fingerprint failure may leave a partial destination which must not be published.
pub fn stream_verified_tls(
    package: &StreamedKexPackage,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    destination: &mut [u8],
) -> Result<(), StreamError> {
    let tls = package
        .executable
        .tls
        .ok_or(StreamError::Tls(Error::InvalidTemplate))?;
    if u64::try_from(destination.len()) != Ok(tls.file_bytes) {
        return Err(StreamError::Tls(Error::InvalidTemplate));
    }
    let start = package
        .executable_offset
        .checked_add(tls.file_offset)
        .ok_or(StreamError::InvalidLength)?;
    let start = usize::try_from(start).map_err(|_| StreamError::InvalidLength)?;
    let end = start
        .checked_add(destination.len())
        .ok_or(StreamError::InvalidLength)?;
    if end > package.package_bytes {
        return Err(StreamError::InvalidLength);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut offset = 0;
    while offset < package.package_bytes {
        let count = (package.package_bytes - offset).min(buffer.len());
        read_stream_exact(&mut read_at, offset as u64, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        let first = offset.max(start);
        let last = (offset + count).min(end);
        if first < last {
            destination[first - start..last - start]
                .copy_from_slice(&buffer[first - offset..last - offset]);
        }
        offset += count;
    }
    if hash.finish() != package.digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
