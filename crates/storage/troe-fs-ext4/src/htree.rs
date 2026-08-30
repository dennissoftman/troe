//! Bounded parsing of the ext4 hashed directory index.
//!
//! An indexed directory keeps its records in ordinary leaf blocks and adds an
//! index that maps a name hash to the leaf holding it. Enumerating a directory
//! therefore only needs the set of leaf blocks; the hash itself is required
//! solely to decide which leaf a new name belongs in.
//!
//! Every index block this module parses is checksum-validated, and every count
//! is bounded by what the block can physically hold.

use alloc::vec::Vec;
use troe_fs_api::FsError;

/// Offset of the index metadata inside a root block, after `.` and `..`.
const DX_ROOT_INFO_OFFSET: usize = 24;
/// Offset of the level count inside the root's index metadata.
const DX_ROOT_LEVELS_OFFSET: usize = DX_ROOT_INFO_OFFSET + 6;
/// Offset of the count/limit pair inside a root block.
pub(crate) const DX_ROOT_COUNT_OFFSET: usize = 32;
/// Offset of the count/limit pair inside an interior node block.
pub(crate) const DX_NODE_COUNT_OFFSET: usize = 8;
/// Bytes per index entry.
const DX_ENTRY_BYTES: usize = 8;
/// Bytes in the trailing checksum record.
const DX_TAIL_BYTES: usize = 8;

/// Hash this provider computes for names it inserts.
pub(crate) const DX_HASH_HALF_MD4: u8 = 1;
/// Legacy hash, still readable.
pub(crate) const DX_HASH_LEGACY: u8 = 0;
/// TEA hash, still readable.
pub(crate) const DX_HASH_TEA: u8 = 2;

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FsError> {
    let field = bytes
        .get(offset..offset.checked_add(2).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?;
    Ok(u16::from_le_bytes(
        <[u8; 2]>::try_from(field).map_err(|_| FsError::Corrupt)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FsError> {
    let field = bytes
        .get(offset..offset.checked_add(4).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?;
    Ok(u32::from_le_bytes(
        <[u8; 4]>::try_from(field).map_err(|_| FsError::Corrupt)?,
    ))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FsError> {
    bytes
        .get_mut(offset..offset.checked_add(2).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), FsError> {
    bytes
        .get_mut(offset..offset.checked_add(4).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// One index entry: the lowest hash in a subtree and the logical block that
/// holds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DxEntry {
    /// Lowest name hash this subtree covers; the first entry covers everything
    /// below the second entry's hash.
    pub(crate) hash: u32,
    /// Logical block within the directory.
    pub(crate) block: u32,
}

/// The parsed root of a hashed directory index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DxRoot {
    /// Hash function the directory was built with.
    pub(crate) hash_version: u8,
    /// Zero for a single level of leaves, one for one level of interior nodes.
    pub(crate) indirect_levels: u8,
    /// Index entries in ascending hash order.
    pub(crate) entries: Vec<DxEntry>,
}

fn validate_block_size(block: &[u8]) -> Result<usize, FsError> {
    if !matches!(block.len(), 1024 | 2048 | 4096) {
        return Err(FsError::Corrupt);
    }
    Ok(block.len())
}

/// Verify the checksum that covers an index block.
///
/// The record covers the block through the live entries, then the reserved
/// word of the trailing record with the checksum field taken as zero.
fn verify_checksum(
    block: &[u8],
    count_offset: usize,
    count: usize,
    limit: usize,
    inode_seed: u32,
    crc: impl Fn(u32, &[u8]) -> u32,
) -> Result<(), FsError> {
    let tail_offset = count_offset
        .checked_add(limit.checked_mul(DX_ENTRY_BYTES).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Overflow)?;
    let tail = block
        .get(tail_offset..tail_offset + DX_TAIL_BYTES)
        .ok_or(FsError::Corrupt)?;
    let covered = count_offset
        .checked_add(count.checked_mul(DX_ENTRY_BYTES).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Overflow)?;
    let mut checksum = crc(inode_seed, block.get(..covered).ok_or(FsError::Corrupt)?);
    checksum = crc(checksum, tail.get(..4).ok_or(FsError::Corrupt)?);
    checksum = crc(checksum, &[0_u8; 4]);
    if read_u32(tail, 4)? != checksum {
        return Err(FsError::Corrupt);
    }
    Ok(())
}

/// Read the entry array shared by root and interior node blocks.
fn parse_entries(
    block: &[u8],
    count_offset: usize,
    inode_seed: u32,
    crc: impl Fn(u32, &[u8]) -> u32,
) -> Result<Vec<DxEntry>, FsError> {
    let block_bytes = validate_block_size(block)?;
    let limit = usize::from(read_u16(block, count_offset)?);
    let count = usize::from(read_u16(block, count_offset + 2)?);
    // This profile requires metadata checksums, so one entry slot always holds
    // the trailing checksum record.
    let expected_limit = block_bytes
        .checked_sub(count_offset)
        .ok_or(FsError::Corrupt)?
        / DX_ENTRY_BYTES
        - 1;
    if limit != expected_limit || count == 0 || count > limit {
        return Err(FsError::Corrupt);
    }
    verify_checksum(block, count_offset, count, limit, inode_seed, crc)?;

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| FsError::NoSpace)?;
    let mut previous = None;
    for index in 0..count {
        let offset = count_offset
            .checked_add(index.checked_mul(DX_ENTRY_BYTES).ok_or(FsError::Overflow)?)
            .ok_or(FsError::Overflow)?;
        // The first entry reuses its hash field for the count and limit, so it
        // implicitly covers every hash below the second entry.
        let hash = if index == 0 {
            0
        } else {
            read_u32(block, offset)?
        };
        if previous.is_some_and(|last: u32| hash <= last) {
            return Err(FsError::Corrupt);
        }
        previous = Some(hash);
        entries.push(DxEntry {
            hash,
            block: read_u32(block, offset + 4)?,
        });
    }
    Ok(entries)
}

/// Parse the root block of a hashed directory index.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] on a malformed root and
/// [`FsError::Unsupported`] when the directory uses a hash this provider does
/// not implement or more index levels than it walks.
pub(crate) fn parse_root(
    block: &[u8],
    inode_seed: u32,
    crc: impl Fn(u32, &[u8]) -> u32,
) -> Result<DxRoot, FsError> {
    let block_bytes = validate_block_size(block)?;
    // `.` and `..` occupy fixed records, and `..` spans the rest of the block
    // so that an unaware reader sees no entries beyond them.
    if read_u16(block, 4)? != 12
        || block.get(6).copied().ok_or(FsError::Corrupt)? != 1
        || block.get(8..9).ok_or(FsError::Corrupt)? != b"."
        || usize::from(read_u16(block, 16)?) != block_bytes - 12
        || block.get(18).copied().ok_or(FsError::Corrupt)? != 2
        || block.get(20..22).ok_or(FsError::Corrupt)? != b".."
    {
        return Err(FsError::Corrupt);
    }
    if read_u32(block, DX_ROOT_INFO_OFFSET)? != 0
        || block
            .get(DX_ROOT_INFO_OFFSET + 5)
            .copied()
            .ok_or(FsError::Corrupt)?
            != 8
        || block
            .get(DX_ROOT_INFO_OFFSET + 7)
            .copied()
            .ok_or(FsError::Corrupt)?
            != 0
    {
        return Err(FsError::Corrupt);
    }
    let hash_version = block
        .get(DX_ROOT_INFO_OFFSET + 4)
        .copied()
        .ok_or(FsError::Corrupt)?;
    let indirect_levels = block
        .get(DX_ROOT_INFO_OFFSET + 6)
        .copied()
        .ok_or(FsError::Corrupt)?;
    if !matches!(
        hash_version,
        DX_HASH_LEGACY | DX_HASH_HALF_MD4 | DX_HASH_TEA
    ) {
        return Err(FsError::Unsupported);
    }
    if indirect_levels > 1 {
        return Err(FsError::Unsupported);
    }
    Ok(DxRoot {
        hash_version,
        indirect_levels,
        entries: parse_entries(block, DX_ROOT_COUNT_OFFSET, inode_seed, crc)?,
    })
}

/// Parse one interior index node.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] when the block is not a well-formed node.
pub(crate) fn parse_node(
    block: &[u8],
    inode_seed: u32,
    crc: impl Fn(u32, &[u8]) -> u32,
) -> Result<Vec<DxEntry>, FsError> {
    let block_bytes = validate_block_size(block)?;
    // An interior node hides behind one empty record spanning the whole block.
    if read_u32(block, 0)? != 0
        || usize::from(read_u16(block, 4)?) != block_bytes
        || block.get(6).copied().ok_or(FsError::Corrupt)? != 0
        || block.get(7).copied().ok_or(FsError::Corrupt)? != 0
    {
        return Err(FsError::Corrupt);
    }
    parse_entries(block, DX_NODE_COUNT_OFFSET, inode_seed, crc)
}

/// Superblock offset of the four-word directory hash seed.
const DX_HASH_SEED_OFFSET: usize = 236;
/// Superblock offset of the miscellaneous flag word.
const DX_FLAGS_OFFSET: usize = 352;
const DX_FLAG_SIGNED_HASH: u32 = 0x0000_0001;
const DX_FLAG_UNSIGNED_HASH: u32 = 0x0000_0002;

const MD4_K2: u32 = 0x5A82_7999;
const MD4_K3: u32 = 0x6ED9_EBA1;
const TEA_DELTA: u32 = 0x9E37_79B9;

/// The filesystem-wide inputs to a directory name hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DxHash {
    seed: [u32; 4],
    /// Whether name bytes are read as signed. `None` when the volume records
    /// no choice, in which case a name's hash cannot be reproduced safely.
    signed_bytes: Option<bool>,
}

impl DxHash {
    /// Read the hash inputs from the filesystem superblock.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Corrupt`] when the superblock is too short.
    pub(crate) fn parse(superblock: &[u8]) -> Result<Self, FsError> {
        let mut seed = [0_u32; 4];
        for (index, word) in seed.iter_mut().enumerate() {
            *word = read_u32(superblock, DX_HASH_SEED_OFFSET + index * 4)?;
        }
        let flags = read_u32(superblock, DX_FLAGS_OFFSET)?;
        let signed_bytes = match (
            flags & DX_FLAG_SIGNED_HASH != 0,
            flags & DX_FLAG_UNSIGNED_HASH != 0,
        ) {
            (true, false) => Some(true),
            (false, true) => Some(false),
            // Both or neither leaves the authoring host's choice unknown.
            _ => None,
        };
        Ok(Self { seed, signed_bytes })
    }

    /// Whether a name's hash can be reproduced on this volume.
    #[cfg(test)]
    pub(crate) const fn is_reproducible(self) -> bool {
        self.signed_bytes.is_some()
    }

    /// Hash one directory name exactly as ext4 does.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Unsupported`] when the volume records no byte
    /// signedness or the directory uses a hash this provider cannot compute.
    pub(crate) fn hash(self, name: &[u8], version: u8) -> Result<u32, FsError> {
        let Some(signed_bytes) = self.signed_bytes else {
            return Err(FsError::Unsupported);
        };
        let mut buffer = if self.seed.iter().all(|word| *word != 0) {
            self.seed
        } else {
            [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]
        };
        let hash = match version {
            DX_HASH_LEGACY => legacy_hash(name, signed_bytes),
            DX_HASH_HALF_MD4 => {
                let mut remaining = name;
                loop {
                    let words = pack_name(remaining, 8, signed_bytes);
                    let value = half_md4_transform(&mut buffer, &words);
                    if remaining.len() <= 32 {
                        break value;
                    }
                    remaining = &remaining[32..];
                }
            }
            DX_HASH_TEA => {
                let mut remaining = name;
                loop {
                    let words = pack_name(remaining, 4, signed_bytes);
                    let mut input = [0_u32; 4];
                    input.copy_from_slice(&words[..4]);
                    tea_transform(&mut buffer, &input);
                    if remaining.len() <= 16 {
                        break buffer[0];
                    }
                    remaining = &remaining[16..];
                }
            }
            _ => return Err(FsError::Unsupported),
        };
        // The low bit distinguishes an index entry from a continuation, and one
        // value is reserved to mark the end of a hash range.
        let hash = hash & !1;
        if hash == 0xFFFF_FFFE {
            return Ok(0xFFFF_FFFC);
        }
        Ok(hash)
    }
}

/// Widen one name byte the way the authoring host's `char` type did.
///
/// A signed byte at or above 0x80 sign-extends; an unsigned one never does.
const fn name_byte(byte: u8, signed_bytes: bool) -> u32 {
    if signed_bytes && byte >= 0x80 {
        0xFFFF_FF00 | (byte as u32)
    } else {
        byte as u32
    }
}

/// Pack up to `words * 4` name bytes into big-endian-ordered words, padding the
/// remainder with the repeated length exactly as ext4 does.
fn pack_name(name: &[u8], words: usize, signed_bytes: bool) -> [u32; 8] {
    let length = u32::try_from(name.len()).unwrap_or(u32::MAX);
    let pad = (length | (length << 8)) | ((length | (length << 8)) << 16);
    let mut packed = [pad; 8];
    let usable = name.len().min(words * 4);
    let mut value = pad;
    let mut produced = 0_usize;
    for (index, byte) in name.iter().take(usable).enumerate() {
        value = name_byte(*byte, signed_bytes).wrapping_add(value << 8);
        if index % 4 == 3 {
            packed[produced] = value;
            produced += 1;
            value = pad;
        }
    }
    if produced < words {
        packed[produced] = value;
    }
    packed
}

/// One MD4 round: `a = rol(a + f(b, c, d) + x, shift)`.
fn round(a: u32, mixed: u32, x: u32, shift: u32) -> u32 {
    a.wrapping_add(mixed).wrapping_add(x).rotate_left(shift)
}

fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y).wrapping_add((x ^ y) & z)
}

fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// The half-MD4 transform ext4 uses, returning the major hash word.
fn half_md4_transform(buffer: &mut [u32; 4], input: &[u32; 8]) -> u32 {
    let (mut a, mut b, mut c, mut d) = (buffer[0], buffer[1], buffer[2], buffer[3]);

    // Round one.
    a = round(a, md4_f(b, c, d), input[0], 3);
    d = round(d, md4_f(a, b, c), input[1], 7);
    c = round(c, md4_f(d, a, b), input[2], 11);
    b = round(b, md4_f(c, d, a), input[3], 19);
    a = round(a, md4_f(b, c, d), input[4], 3);
    d = round(d, md4_f(a, b, c), input[5], 7);
    c = round(c, md4_f(d, a, b), input[6], 11);
    b = round(b, md4_f(c, d, a), input[7], 19);

    // Round two.
    a = round(a, md4_g(b, c, d), input[1].wrapping_add(MD4_K2), 3);
    d = round(d, md4_g(a, b, c), input[3].wrapping_add(MD4_K2), 5);
    c = round(c, md4_g(d, a, b), input[5].wrapping_add(MD4_K2), 9);
    b = round(b, md4_g(c, d, a), input[7].wrapping_add(MD4_K2), 13);
    a = round(a, md4_g(b, c, d), input[0].wrapping_add(MD4_K2), 3);
    d = round(d, md4_g(a, b, c), input[2].wrapping_add(MD4_K2), 5);
    c = round(c, md4_g(d, a, b), input[4].wrapping_add(MD4_K2), 9);
    b = round(b, md4_g(c, d, a), input[6].wrapping_add(MD4_K2), 13);

    // Round three.
    a = round(a, md4_h(b, c, d), input[3].wrapping_add(MD4_K3), 3);
    d = round(d, md4_h(a, b, c), input[7].wrapping_add(MD4_K3), 9);
    c = round(c, md4_h(d, a, b), input[2].wrapping_add(MD4_K3), 11);
    b = round(b, md4_h(c, d, a), input[6].wrapping_add(MD4_K3), 15);
    a = round(a, md4_h(b, c, d), input[1].wrapping_add(MD4_K3), 3);
    d = round(d, md4_h(a, b, c), input[5].wrapping_add(MD4_K3), 9);
    c = round(c, md4_h(d, a, b), input[0].wrapping_add(MD4_K3), 11);
    b = round(b, md4_h(c, d, a), input[4].wrapping_add(MD4_K3), 15);

    buffer[0] = buffer[0].wrapping_add(a);
    buffer[1] = buffer[1].wrapping_add(b);
    buffer[2] = buffer[2].wrapping_add(c);
    buffer[3] = buffer[3].wrapping_add(d);
    buffer[1]
}

fn tea_transform(buffer: &mut [u32; 4], input: &[u32; 4]) {
    let mut sum = 0_u32;
    let (mut b0, mut b1) = (buffer[0], buffer[1]);
    let (a, b, c, d) = (input[0], input[1], input[2], input[3]);
    for _ in 0..16 {
        sum = sum.wrapping_add(TEA_DELTA);
        b0 = b0.wrapping_add(
            ((b1 << 4).wrapping_add(a)) ^ (b1.wrapping_add(sum)) ^ ((b1 >> 5).wrapping_add(b)),
        );
        b1 = b1.wrapping_add(
            ((b0 << 4).wrapping_add(c)) ^ (b0.wrapping_add(sum)) ^ ((b0 >> 5).wrapping_add(d)),
        );
    }
    buffer[0] = buffer[0].wrapping_add(b0);
    buffer[1] = buffer[1].wrapping_add(b1);
}

/// The pre-index hash ext4 still accepts on old directories.
fn legacy_hash(name: &[u8], signed_bytes: bool) -> u32 {
    let mut hash0 = 0x12a3_fe2d_u32;
    let mut hash1 = 0x37ab_e8f9_u32;
    for byte in name {
        let extended = if signed_bytes {
            #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
            {
                i32::from(*byte as i8) as u32
            }
        } else {
            u32::from(*byte)
        };
        let mut hash = hash1.wrapping_add(hash0 ^ extended.wrapping_mul(7_152_373));
        if hash & 0x8000_0000 != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        hash1 = hash0;
        hash0 = hash;
    }
    hash0 << 1
}

/// Entries one index block of this size holds at the given array offset.
///
/// This profile requires metadata checksums, so the last entry slot always
/// holds the trailing checksum record rather than an entry.
pub(crate) fn entry_capacity(block_bytes: usize, count_offset: usize) -> Result<usize, FsError> {
    validate_block_size_of(block_bytes)?;
    block_bytes
        .checked_sub(count_offset)
        .map(|span| span / DX_ENTRY_BYTES)
        .and_then(|slots| slots.checked_sub(1))
        .filter(|capacity| *capacity != 0)
        .ok_or(FsError::Corrupt)
}

fn validate_block_size_of(block_bytes: usize) -> Result<(), FsError> {
    if !matches!(block_bytes, 1024 | 2048 | 4096) {
        return Err(FsError::Corrupt);
    }
    Ok(())
}

/// Turn a freshly allocated block into an empty interior index node.
///
/// The node hides behind one empty record spanning the whole block, so a
/// reader that does not know about the index sees no entries in it at all.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] for a block this profile does not use.
pub(crate) fn initialize_node(block: &mut [u8]) -> Result<(), FsError> {
    validate_block_size(block)?;
    block.fill(0);
    put_u16(
        block,
        4,
        u16::try_from(block.len()).map_err(|_| FsError::Overflow)?,
    )
}

/// Record how many interior levels the root's children stand above the leaves.
///
/// This byte is inside the range the root checksum covers, so it must be set
/// before the entries are written.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] when the block is too short.
pub(crate) fn set_indirect_levels(block: &mut [u8], levels: u8) -> Result<(), FsError> {
    *block
        .get_mut(DX_ROOT_LEVELS_OFFSET)
        .ok_or(FsError::Corrupt)? = levels;
    Ok(())
}

/// Replace the entry array of a root or interior node and refresh its checksum.
///
/// The first entry's hash field is where the count and limit live, so that
/// entry implicitly covers every hash below the second one and its own hash
/// must be zero. Callers that promote a subtree pass its real lowest hash to
/// the parent instead.
///
/// # Errors
///
/// Returns [`FsError::NoSpace`] when the entries do not fit and
/// [`FsError::Corrupt`] when they are unordered or the block is malformed.
pub(crate) fn write_entries(
    block: &mut [u8],
    count_offset: usize,
    entries: &[DxEntry],
    inode_seed: u32,
    crc: impl Fn(u32, &[u8]) -> u32,
) -> Result<(), FsError> {
    let limit = entry_capacity(block.len(), count_offset)?;
    let first = entries.first().ok_or(FsError::Corrupt)?;
    if entries.len() > limit {
        return Err(FsError::NoSpace);
    }
    if first.hash != 0 || entries.windows(2).any(|pair| pair[1].hash <= pair[0].hash) {
        return Err(FsError::Corrupt);
    }
    put_u16(
        block,
        count_offset,
        u16::try_from(limit).map_err(|_| FsError::Overflow)?,
    )?;
    put_u16(
        block,
        count_offset + 2,
        u16::try_from(entries.len()).map_err(|_| FsError::Overflow)?,
    )?;
    for (index, entry) in entries.iter().enumerate() {
        let offset = count_offset
            .checked_add(index.checked_mul(DX_ENTRY_BYTES).ok_or(FsError::Overflow)?)
            .ok_or(FsError::Overflow)?;
        if index != 0 {
            put_u32(block, offset, entry.hash)?;
        }
        put_u32(block, offset + 4, entry.block)?;
    }
    let used = count_offset
        .checked_add(
            entries
                .len()
                .checked_mul(DX_ENTRY_BYTES)
                .ok_or(FsError::Overflow)?,
        )
        .ok_or(FsError::Overflow)?;
    let tail_offset = count_offset
        .checked_add(limit.checked_mul(DX_ENTRY_BYTES).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Overflow)?;
    // Retired slots keep no stale entry, and the trailing record's reserved
    // word is zero because the checksum is computed over it.
    block
        .get_mut(used..tail_offset + 4)
        .ok_or(FsError::Corrupt)?
        .fill(0);
    let mut checksum = crc(inode_seed, block.get(..used).ok_or(FsError::Corrupt)?);
    checksum = crc(checksum, &[0_u8; 4]);
    checksum = crc(checksum, &[0_u8; 4]);
    put_u32(block, tail_offset + 4, checksum)
}
