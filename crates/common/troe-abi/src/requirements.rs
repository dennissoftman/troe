//! Canonical package-side declaration of optional startup authorities.

/// Product-independent capability-manifest format identifier.
pub const MAGIC: [u8; 8] = *b"KCAPv1\0\0";
/// Fixed manifest header bytes.
pub const HEADER_BYTES: usize = 16;
/// Fixed bytes per required interface.
pub const RECORD_BYTES: usize = 8;
/// Maximum optional startup authorities declared by one package.
pub const MAX_REQUIREMENTS: usize = 128;
/// Largest canonical manifest accepted by the kernel.
pub const MAX_MANIFEST_BYTES: usize = HEADER_BYTES + MAX_REQUIREMENTS * RECORD_BYTES;

/// One exact interface version required at application startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirement {
    /// Stable interface identifier.
    pub interface: u32,
    /// Required interface major version.
    pub major: u16,
    /// Required interface minor version.
    pub minor: u16,
}

/// Invalid, excessive, unsorted, or noncanonical manifest bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Borrowed validated capability manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> Manifest<'a> {
    /// Parse one exact manifest without allocation.
    ///
    /// # Errors
    ///
    /// Rejects every truncation, trailing byte, reserved field, zero
    /// identifier/version, duplicate, or non-ascending interface record.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EncodingError> {
        if bytes.len() < HEADER_BYTES || bytes[..8] != MAGIC {
            return Err(EncodingError);
        }
        let count = usize::from(read_u16(bytes, 8)?);
        let expected = HEADER_BYTES
            .checked_add(count.checked_mul(RECORD_BYTES).ok_or(EncodingError)?)
            .ok_or(EncodingError)?;
        if count > MAX_REQUIREMENTS
            || read_u16(bytes, 10)? != 0
            || usize::try_from(read_u32(bytes, 12)?).map_err(|_| EncodingError)? != expected
            || bytes.len() != expected
        {
            return Err(EncodingError);
        }
        let manifest = Self { bytes, count };
        let mut previous = 0_u32;
        for requirement in manifest.iter() {
            if requirement.interface <= previous || requirement.major == 0 {
                return Err(EncodingError);
            }
            previous = requirement.interface;
        }
        Ok(manifest)
    }

    /// Number of optional authorities required by the package.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }

    /// Whether the package requests no optional authority.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Iterate through ascending, unique interface requirements.
    #[must_use]
    pub const fn iter(self) -> Requirements<'a> {
        Requirements {
            manifest: self,
            index: 0,
        }
    }
}

/// Iterator over validated interface requirements.
pub struct Requirements<'a> {
    manifest: Manifest<'a>,
    index: usize,
}

impl Iterator for Requirements<'_> {
    type Item = Requirement;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.manifest.count {
            return None;
        }
        let offset = HEADER_BYTES + self.index * RECORD_BYTES;
        self.index += 1;
        Some(Requirement {
            interface: read_u32(self.manifest.bytes, offset).ok()?,
            major: read_u16(self.manifest.bytes, offset + 4).ok()?,
            minor: read_u16(self.manifest.bytes, offset + 6).ok()?,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.manifest.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Requirements<'_> {}

/// Encode ascending, unique optional interface requirements.
///
/// # Errors
///
/// Rejects policy excess, zero identifier/version, non-ascending records,
/// or insufficient destination storage without modifying it.
pub fn encode(
    requirements: &[Requirement],
    destination: &mut [u8],
) -> Result<usize, EncodingError> {
    let count = requirements.len();
    let encoded_bytes = HEADER_BYTES
        .checked_add(count.checked_mul(RECORD_BYTES).ok_or(EncodingError)?)
        .ok_or(EncodingError)?;
    if count > MAX_REQUIREMENTS || destination.len() < encoded_bytes {
        return Err(EncodingError);
    }
    let mut previous = 0_u32;
    for requirement in requirements {
        if requirement.interface <= previous || requirement.major == 0 {
            return Err(EncodingError);
        }
        previous = requirement.interface;
    }
    let mut encoded = [0_u8; MAX_MANIFEST_BYTES];
    encoded[..8].copy_from_slice(&MAGIC);
    encoded[8..10].copy_from_slice(
        &u16::try_from(count)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    encoded[12..16].copy_from_slice(
        &u32::try_from(encoded_bytes)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    for (index, requirement) in requirements.iter().enumerate() {
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        encoded[offset..offset + 4].copy_from_slice(&requirement.interface.to_le_bytes());
        encoded[offset + 4..offset + 6].copy_from_slice(&requirement.major.to_le_bytes());
        encoded[offset + 6..offset + 8].copy_from_slice(&requirement.minor.to_le_bytes());
    }
    destination[..encoded_bytes].copy_from_slice(&encoded[..encoded_bytes]);
    Ok(encoded_bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
    let raw = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use crate::{datagram, interface, requirements};

    #[test]
    fn capability_manifest_is_exact_sorted_and_allocation_free() {
        let declared = [requirements::Requirement {
            interface: interface::DATAGRAM,
            major: datagram::MAJOR,
            minor: datagram::MINOR,
        }];
        let mut bytes = [0xa5_u8; requirements::MAX_MANIFEST_BYTES];
        let count =
            requirements::encode(&declared, &mut bytes).unwrap_or_else(|_| std::process::abort());
        let parsed = requirements::Manifest::parse(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(parsed.iter().collect::<std::vec::Vec<_>>(), declared);
        for end in 0..count {
            assert!(requirements::Manifest::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(requirements::Manifest::parse(&trailing).is_err());

        let duplicate = [declared[0], declared[0]];
        let mut unchanged = [0xa5_u8; requirements::MAX_MANIFEST_BYTES];
        assert!(requirements::encode(&duplicate, &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; requirements::MAX_MANIFEST_BYTES]);
    }
}
