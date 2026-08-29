//! Bounded JBD2 physical-block redo journaling for the constrained ext4 profile.
//!
//! The profile already requires the `has_journal` compatible feature and ships
//! an allocated, initialized internal journal, so this module adds no new
//! on-disk structure. It writes exactly the JBD2 dialect a feature-less journal
//! superblock describes: 8-byte tags, no journal checksums, no revoke records,
//! and no 64-bit block numbers.
//!
//! One mutation is one transaction, and a transaction is checkpointed and
//! retired before the next one begins. At most one transaction is ever
//! replayable. That invariant is load-bearing: it is the reason this dialect
//! needs no revoke records. Batching mutations into one transaction, or
//! checkpointing lazily, would allow a block journaled as metadata in one
//! transaction to be reallocated as unjournaled file data in the next, and a
//! replay would then silently clobber it.

use alloc::vec::Vec;
use troe_vfs::FsError;

/// Every JBD2 block begins with this magic in big-endian byte order.
pub(crate) const JBD2_MAGIC: u32 = 0xC03B_3998;

pub(crate) const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub(crate) const JBD2_COMMIT_BLOCK: u32 = 2;
pub(crate) const JBD2_SUPERBLOCK_V2: u32 = 4;

const JBD2_FLAG_ESCAPE: u16 = 0x0001;
const JBD2_FLAG_SAME_UUID: u16 = 0x0002;
const JBD2_FLAG_LAST_TAG: u16 = 0x0008;
const JBD2_KNOWN_FLAGS: u16 = JBD2_FLAG_ESCAPE | JBD2_FLAG_SAME_UUID | JBD2_FLAG_LAST_TAG;

/// Header length shared by descriptor, commit, and superblock blocks.
const JBD2_HEADER_BYTES: usize = 12;
/// Tag length when neither a journal checksum nor 64-bit block numbers are set.
const JBD2_TAG_BYTES: usize = 8;
/// Length of the UUID that follows a tag without `SAME_UUID`.
const JBD2_UUID_BYTES: usize = 16;

/// The hard ceiling on payload blocks in one TROE transaction.
///
/// The worst admissible geometry touches the superblock, the group-descriptor
/// table, one block and one inode bitmap per touched group, at most four
/// inode-table blocks, at most four extent leaves, at most three directory
/// blocks, and one journaled data block. The shipped 16 MiB single-group
/// volume needs about sixteen. This ceiling is checked before the first
/// buffered write so a transaction can never overflow the log after payload
/// has already reached media.
pub(crate) const MAX_TRANSACTION_BLOCKS: usize = 128;

fn read_be32(bytes: &[u8], offset: usize) -> Result<u32, FsError> {
    let field = bytes
        .get(offset..offset.checked_add(4).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?;
    let raw = <[u8; 4]>::try_from(field).map_err(|_| FsError::Corrupt)?;
    Ok(u32::from_be_bytes(raw))
}

fn put_be32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), FsError> {
    let field = bytes
        .get_mut(offset..offset.checked_add(4).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?;
    field.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_be16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FsError> {
    let field = bytes
        .get_mut(offset..offset.checked_add(2).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?;
    field.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn read_be16(bytes: &[u8], offset: usize) -> Result<u16, FsError> {
    let field = bytes
        .get(offset..offset.checked_add(2).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?;
    let raw = <[u8; 2]>::try_from(field).map_err(|_| FsError::Corrupt)?;
    Ok(u16::from_be_bytes(raw))
}

/// The parsed internal-journal superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalSuperblock {
    /// Journal block size in bytes; must equal the filesystem block size.
    pub(crate) blocksize: u32,
    /// Total journal blocks including the superblock at journal block 0.
    pub(crate) maxlen: u32,
    /// First journal block that may hold log records.
    pub(crate) first: u32,
    /// Sequence the head transaction is expected to carry.
    pub(crate) sequence: u32,
    /// Journal block of the head transaction, or zero when the log is clean.
    pub(crate) start: u32,
    /// Journal UUID as stored, never byte-swapped.
    pub(crate) uuid: [u8; JBD2_UUID_BYTES],
}

impl JournalSuperblock {
    /// Parse the journal superblock from journal block zero.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Unsupported`] when the journal declares any feature
    /// this profile does not emit, and [`FsError::Corrupt`] on a malformed or
    /// self-inconsistent superblock.
    pub(crate) fn parse(block: &[u8], fs_block_bytes: u32) -> Result<Self, FsError> {
        if read_be32(block, 0)? != JBD2_MAGIC || read_be32(block, 4)? != JBD2_SUPERBLOCK_V2 {
            return Err(FsError::Unsupported);
        }
        // This profile emits no journal checksums, no revoke records, and no
        // 64-bit block numbers. Any feature bit means foreign authorship.
        if read_be32(block, 0x24)? != 0
            || read_be32(block, 0x28)? != 0
            || read_be32(block, 0x2C)? != 0
            || block.get(0x50).copied().ok_or(FsError::Corrupt)? != 0
        {
            return Err(FsError::Unsupported);
        }
        let blocksize = read_be32(block, 0x0C)?;
        let maxlen = read_be32(block, 0x10)?;
        let first = read_be32(block, 0x14)?;
        let sequence = read_be32(block, 0x18)?;
        let start = read_be32(block, 0x1C)?;
        if blocksize != fs_block_bytes
            || maxlen < 2
            || first == 0
            || first >= maxlen
            || sequence == 0
            || start >= maxlen
            || (start != 0 && start < first)
            || read_be32(block, 0x40)? != 1
        {
            return Err(FsError::Corrupt);
        }
        let uuid =
            <[u8; JBD2_UUID_BYTES]>::try_from(block.get(0x30..0x40).ok_or(FsError::Corrupt)?)
                .map_err(|_| FsError::Corrupt)?;
        Ok(Self {
            blocksize,
            maxlen,
            first,
            sequence,
            start,
            uuid,
        })
    }

    /// Rewrite only the head and sequence fields of an existing superblock.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Corrupt`] when the block is too short.
    pub(crate) fn write_head(block: &mut [u8], start: u32, sequence: u32) -> Result<(), FsError> {
        put_be32(block, 0x18, sequence)?;
        put_be32(block, 0x1C, start)
    }

    /// Return the number of log blocks available for one transaction.
    pub(crate) fn usable_blocks(&self) -> u32 {
        self.maxlen.saturating_sub(self.first)
    }
}

/// One block image staged for the log, addressed by filesystem block number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StagedBlock {
    /// Destination filesystem block.
    pub(crate) block: u32,
    /// The complete post-state image of that block.
    pub(crate) image: Vec<u8>,
}

/// Encode one complete transaction as consecutive journal block images.
///
/// The returned images are written at consecutive journal blocks starting at
/// `head`: one descriptor, then one image per staged block in order, then the
/// commit block. The caller must flush the descriptor and every data block
/// before it writes the commit block.
///
/// # Errors
///
/// Returns [`FsError::NoSpace`] when the transaction cannot fit the log or
/// exceeds [`MAX_TRANSACTION_BLOCKS`], and [`FsError::Invalid`] on a malformed
/// staging set.
pub(crate) fn encode_transaction(
    superblock: &JournalSuperblock,
    sequence: u32,
    staged: &[StagedBlock],
) -> Result<Vec<Vec<u8>>, FsError> {
    let block_bytes = usize::try_from(superblock.blocksize).map_err(|_| FsError::Corrupt)?;
    if staged.is_empty() || staged.len() > MAX_TRANSACTION_BLOCKS {
        return Err(FsError::NoSpace);
    }
    let required = staged.len().checked_add(2).ok_or(FsError::Overflow)?;
    let usable = usize::try_from(superblock.usable_blocks()).map_err(|_| FsError::Corrupt)?;
    if required > usable {
        return Err(FsError::NoSpace);
    }
    // One descriptor block must hold every tag; the profile never spans two.
    let tag_span = staged
        .len()
        .checked_mul(JBD2_TAG_BYTES)
        .and_then(|span| span.checked_add(JBD2_UUID_BYTES))
        .and_then(|span| span.checked_add(JBD2_HEADER_BYTES))
        .ok_or(FsError::Overflow)?;
    if tag_span > block_bytes {
        return Err(FsError::NoSpace);
    }

    let mut images: Vec<Vec<u8>> = Vec::new();
    images
        .try_reserve_exact(required)
        .map_err(|_| FsError::NoSpace)?;

    let mut descriptor = Vec::new();
    descriptor
        .try_reserve_exact(block_bytes)
        .map_err(|_| FsError::NoSpace)?;
    descriptor.resize(block_bytes, 0);
    put_be32(&mut descriptor, 0, JBD2_MAGIC)?;
    put_be32(&mut descriptor, 4, JBD2_DESCRIPTOR_BLOCK)?;
    put_be32(&mut descriptor, 8, sequence)?;

    let mut offset = JBD2_HEADER_BYTES;
    let mut payload: Vec<Vec<u8>> = Vec::new();
    payload
        .try_reserve_exact(staged.len())
        .map_err(|_| FsError::NoSpace)?;
    for (index, entry) in staged.iter().enumerate() {
        if entry.image.len() != block_bytes {
            return Err(FsError::Invalid);
        }
        let mut flags = 0_u16;
        if index != 0 {
            flags |= JBD2_FLAG_SAME_UUID;
        }
        if index == staged.len() - 1 {
            flags |= JBD2_FLAG_LAST_TAG;
        }
        let mut image = Vec::new();
        image
            .try_reserve_exact(block_bytes)
            .map_err(|_| FsError::NoSpace)?;
        image.extend_from_slice(&entry.image);
        // A journaled block whose first word would be mistaken for a journal
        // record is escaped: the word is zeroed in the log and restored by
        // replay.
        if read_be32(&image, 0)? == JBD2_MAGIC {
            flags |= JBD2_FLAG_ESCAPE;
            put_be32(&mut image, 0, 0)?;
        }
        put_be32(&mut descriptor, offset, entry.block)?;
        put_be16(&mut descriptor, offset + 4, 0)?;
        put_be16(&mut descriptor, offset + 6, flags)?;
        offset = offset
            .checked_add(JBD2_TAG_BYTES)
            .ok_or(FsError::Overflow)?;
        if index == 0 {
            descriptor
                .get_mut(offset..offset + JBD2_UUID_BYTES)
                .ok_or(FsError::Corrupt)?
                .copy_from_slice(&superblock.uuid);
            offset = offset
                .checked_add(JBD2_UUID_BYTES)
                .ok_or(FsError::Overflow)?;
        }
        payload.push(image);
    }

    let mut commit = Vec::new();
    commit
        .try_reserve_exact(block_bytes)
        .map_err(|_| FsError::NoSpace)?;
    commit.resize(block_bytes, 0);
    put_be32(&mut commit, 0, JBD2_MAGIC)?;
    put_be32(&mut commit, 4, JBD2_COMMIT_BLOCK)?;
    put_be32(&mut commit, 8, sequence)?;

    images.push(descriptor);
    images.extend(payload);
    images.push(commit);
    Ok(images)
}

/// One tag decoded from a descriptor block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodedTag {
    /// Destination filesystem block.
    pub(crate) block: u32,
    /// Whether replay must restore the escaped magic word.
    pub(crate) escaped: bool,
}

/// Decode every tag in one descriptor block.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] when the header, sequence, flags, or tag array
/// are malformed, and [`FsError::NoSpace`] when the tag count exceeds the
/// transaction ceiling.
pub(crate) fn decode_descriptor(
    block: &[u8],
    sequence: u32,
    volume_blocks: u32,
) -> Result<Vec<DecodedTag>, FsError> {
    if read_be32(block, 0)? != JBD2_MAGIC
        || read_be32(block, 4)? != JBD2_DESCRIPTOR_BLOCK
        || read_be32(block, 8)? != sequence
    {
        return Err(FsError::Corrupt);
    }
    let mut tags: Vec<DecodedTag> = Vec::new();
    let mut offset = JBD2_HEADER_BYTES;
    loop {
        if offset
            .checked_add(JBD2_TAG_BYTES)
            .ok_or(FsError::Overflow)?
            > block.len()
        {
            return Err(FsError::Corrupt);
        }
        let destination = read_be32(block, offset)?;
        let flags = read_be16(block, offset + 6)?;
        // Block 0 is legitimately journaled: the ext4 superblock's free
        // counters are rewritten inside a mutation.
        if flags & !JBD2_KNOWN_FLAGS != 0 || destination >= volume_blocks {
            return Err(FsError::Corrupt);
        }
        if tags.is_empty() == (flags & JBD2_FLAG_SAME_UUID != 0) {
            return Err(FsError::Corrupt);
        }
        if tags.len() >= MAX_TRANSACTION_BLOCKS {
            return Err(FsError::NoSpace);
        }
        tags.try_reserve(1).map_err(|_| FsError::NoSpace)?;
        tags.push(DecodedTag {
            block: destination,
            escaped: flags & JBD2_FLAG_ESCAPE != 0,
        });
        offset = offset
            .checked_add(JBD2_TAG_BYTES)
            .ok_or(FsError::Overflow)?;
        if flags & JBD2_FLAG_SAME_UUID == 0 {
            offset = offset
                .checked_add(JBD2_UUID_BYTES)
                .ok_or(FsError::Overflow)?;
        }
        if flags & JBD2_FLAG_LAST_TAG != 0 {
            return Ok(tags);
        }
    }
}

/// Confirm that a block is the commit record of exactly this transaction.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] when the block is not that commit record.
pub(crate) fn verify_commit(block: &[u8], sequence: u32) -> Result<(), FsError> {
    if read_be32(block, 0)? != JBD2_MAGIC
        || read_be32(block, 4)? != JBD2_COMMIT_BLOCK
        || read_be32(block, 8)? != sequence
    {
        return Err(FsError::Corrupt);
    }
    Ok(())
}

/// Restore the escaped first word of a replayed block image.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] when the image is too short.
pub(crate) fn unescape(image: &mut [u8]) -> Result<(), FsError> {
    put_be32(image, 0, JBD2_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::{
        DecodedTag, JBD2_COMMIT_BLOCK, JBD2_MAGIC, JBD2_SUPERBLOCK_V2, JournalSuperblock,
        MAX_TRANSACTION_BLOCKS, StagedBlock, decode_descriptor, encode_transaction, unescape,
        verify_commit,
    };
    use alloc::vec;
    use alloc::vec::Vec;
    use troe_vfs::FsError;

    const BLOCK_BYTES: usize = 4096;
    const UUID: [u8; 16] = *b"troe-ext4-test!!";
    const VOLUME_BLOCKS: u32 = 4096;

    /// Build the journal superblock exactly as `mke2fs 1.47.4` writes it.
    fn superblock_image(maxlen: u32, start: u32, sequence: u32) -> Vec<u8> {
        let mut block = vec![0_u8; BLOCK_BYTES];
        block[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        block[4..8].copy_from_slice(&JBD2_SUPERBLOCK_V2.to_be_bytes());
        block[0x0C..0x10].copy_from_slice(&4096_u32.to_be_bytes());
        block[0x10..0x14].copy_from_slice(&maxlen.to_be_bytes());
        block[0x14..0x18].copy_from_slice(&1_u32.to_be_bytes());
        block[0x18..0x1C].copy_from_slice(&sequence.to_be_bytes());
        block[0x1C..0x20].copy_from_slice(&start.to_be_bytes());
        block[0x30..0x40].copy_from_slice(&UUID);
        block[0x40..0x44].copy_from_slice(&1_u32.to_be_bytes());
        block
    }

    fn parsed() -> Result<JournalSuperblock, FsError> {
        JournalSuperblock::parse(&superblock_image(1024, 0, 1), 4096)
    }

    #[test]
    fn parses_the_shipped_journal_superblock() -> Result<(), FsError> {
        let superblock = parsed()?;
        assert_eq!(superblock.blocksize, 4096);
        assert_eq!(superblock.maxlen, 1024);
        assert_eq!(superblock.first, 1);
        assert_eq!(superblock.sequence, 1);
        assert_eq!(superblock.start, 0);
        assert_eq!(superblock.uuid, UUID);
        assert_eq!(superblock.usable_blocks(), 1023);
        Ok(())
    }

    #[test]
    fn refuses_every_journal_feature_this_profile_never_emits() {
        for offset in [0x24_usize, 0x28, 0x2C] {
            let mut block = superblock_image(1024, 0, 1);
            block[offset + 3] = 1;
            assert_eq!(
                JournalSuperblock::parse(&block, 4096),
                Err(FsError::Unsupported)
            );
        }
        let mut checksummed = superblock_image(1024, 0, 1);
        checksummed[0x50] = 4;
        assert_eq!(
            JournalSuperblock::parse(&checksummed, 4096),
            Err(FsError::Unsupported)
        );
    }

    #[test]
    fn refuses_foreign_and_self_inconsistent_superblocks() {
        let mut wrong_magic = superblock_image(1024, 0, 1);
        wrong_magic[0] ^= 0xFF;
        assert_eq!(
            JournalSuperblock::parse(&wrong_magic, 4096),
            Err(FsError::Unsupported)
        );

        let mut version_one = superblock_image(1024, 0, 1);
        version_one[7] = 3;
        assert_eq!(
            JournalSuperblock::parse(&version_one, 4096),
            Err(FsError::Unsupported)
        );

        // A journal block size that disagrees with the filesystem is refused.
        assert_eq!(
            JournalSuperblock::parse(&superblock_image(1024, 0, 1), 1024),
            Err(FsError::Corrupt)
        );
        // A head outside the log, or before the first log block, is refused.
        assert_eq!(
            JournalSuperblock::parse(&superblock_image(1024, 1024, 1), 4096),
            Err(FsError::Corrupt)
        );
        // A zero sequence can never match a written transaction.
        assert_eq!(
            JournalSuperblock::parse(&superblock_image(1024, 4, 0), 4096),
            Err(FsError::Corrupt)
        );
    }

    #[test]
    fn truncation_never_panics_and_always_rejects() {
        let complete = superblock_image(1024, 0, 1);
        for length in 0..0x44 {
            assert!(JournalSuperblock::parse(&complete[..length], 4096).is_err());
        }
    }

    #[test]
    fn writes_only_the_head_fields() -> Result<(), FsError> {
        let mut block = superblock_image(1024, 0, 1);
        let untouched = block.clone();
        JournalSuperblock::write_head(&mut block, 5, 7)?;
        let reparsed = JournalSuperblock::parse(&block, 4096)?;
        assert_eq!(reparsed.start, 5);
        assert_eq!(reparsed.sequence, 7);
        for (index, byte) in block.iter().enumerate() {
            if !(0x18..0x20).contains(&index) {
                assert_eq!(*byte, untouched[index], "byte {index} must not move");
            }
        }
        Ok(())
    }

    fn staged(blocks: &[(u32, u8)]) -> Vec<StagedBlock> {
        blocks
            .iter()
            .map(|(block, fill)| StagedBlock {
                block: *block,
                image: vec![*fill; BLOCK_BYTES],
            })
            .collect()
    }

    #[test]
    fn transaction_round_trips_through_the_log() -> Result<(), FsError> {
        let superblock = parsed()?;
        let entries = staged(&[(2, 0xA1), (3, 0xB2), (40, 0xC3)]);
        let images = encode_transaction(&superblock, 9, &entries)?;
        assert_eq!(images.len(), entries.len() + 2);

        let tags = decode_descriptor(&images[0], 9, VOLUME_BLOCKS)?;
        assert_eq!(
            tags,
            vec![
                DecodedTag {
                    block: 2,
                    escaped: false
                },
                DecodedTag {
                    block: 3,
                    escaped: false
                },
                DecodedTag {
                    block: 40,
                    escaped: false
                },
            ]
        );
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(images[index + 1], entry.image);
        }
        verify_commit(&images[images.len() - 1], 9)?;
        Ok(())
    }

    #[test]
    fn a_block_that_looks_like_a_journal_record_is_escaped_and_restored() -> Result<(), FsError> {
        let superblock = parsed()?;
        let mut image = vec![0x5A_u8; BLOCK_BYTES];
        image[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        let entries = vec![StagedBlock {
            block: 7,
            image: image.clone(),
        }];
        let images = encode_transaction(&superblock, 3, &entries)?;

        // The logged copy must not carry the magic that would confuse a scan.
        assert_eq!(images[1][0..4], [0, 0, 0, 0]);
        let tags = decode_descriptor(&images[0], 3, VOLUME_BLOCKS)?;
        assert_eq!(
            tags,
            vec![DecodedTag {
                block: 7,
                escaped: true
            }]
        );

        let mut replayed = images[1].clone();
        unescape(&mut replayed)?;
        assert_eq!(replayed, image, "replay must restore the escaped word");
        Ok(())
    }

    #[test]
    fn a_transaction_that_cannot_fit_the_log_is_refused_before_any_write() -> Result<(), FsError> {
        let superblock = parsed()?;
        assert_eq!(
            encode_transaction(&superblock, 1, &[]),
            Err(FsError::NoSpace)
        );

        let oversized = staged(
            &(0..=u32::try_from(MAX_TRANSACTION_BLOCKS).map_err(|_| FsError::Overflow)?)
                .map(|block| (block + 2, 0))
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            encode_transaction(&superblock, 1, &oversized),
            Err(FsError::NoSpace)
        );

        // A log too short for descriptor + payload + commit is refused.
        let tiny = JournalSuperblock::parse(&superblock_image(4, 0, 1), 4096)?;
        assert_eq!(
            encode_transaction(&tiny, 1, &staged(&[(2, 1), (3, 2), (4, 3)])),
            Err(FsError::NoSpace)
        );
        Ok(())
    }

    #[test]
    fn a_short_or_mistyped_image_is_refused() -> Result<(), FsError> {
        let superblock = parsed()?;
        let short = vec![StagedBlock {
            block: 2,
            image: vec![0; BLOCK_BYTES - 1],
        }];
        assert_eq!(
            encode_transaction(&superblock, 1, &short),
            Err(FsError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn descriptor_decoding_rejects_foreign_and_malformed_records() -> Result<(), FsError> {
        let superblock = parsed()?;
        let images = encode_transaction(&superblock, 5, &staged(&[(2, 1), (3, 2)]))?;

        // A descriptor from a different transaction is never replayed.
        assert_eq!(
            decode_descriptor(&images[0], 6, VOLUME_BLOCKS),
            Err(FsError::Corrupt)
        );
        // A commit record is not a descriptor.
        assert_eq!(
            decode_descriptor(&images[images.len() - 1], 5, VOLUME_BLOCKS),
            Err(FsError::Corrupt)
        );
        // A tag naming a block outside the volume is refused.
        assert_eq!(decode_descriptor(&images[0], 5, 3), Err(FsError::Corrupt));
        // An unknown flag bit means a dialect this profile does not replay.
        let mut unknown = images[0].clone();
        unknown[12 + 6] = 0x40;
        assert_eq!(
            decode_descriptor(&unknown, 5, VOLUME_BLOCKS),
            Err(FsError::Corrupt)
        );
        // A first tag claiming SAME_UUID contradicts the layout.
        let mut misplaced = images[0].clone();
        misplaced[12 + 7] |= 0x02;
        assert_eq!(
            decode_descriptor(&misplaced, 5, VOLUME_BLOCKS),
            Err(FsError::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn a_descriptor_without_a_final_tag_is_refused() -> Result<(), FsError> {
        let superblock = parsed()?;
        let mut images = encode_transaction(&superblock, 2, &staged(&[(2, 1)]))?;
        // Clear LAST_TAG so the scan runs off the end of the block.
        images[0][12 + 7] &= !0x08;
        assert_eq!(
            decode_descriptor(&images[0], 2, VOLUME_BLOCKS),
            Err(FsError::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn commit_verification_binds_the_exact_transaction() -> Result<(), FsError> {
        let superblock = parsed()?;
        let images = encode_transaction(&superblock, 11, &staged(&[(2, 1)]))?;
        let commit = &images[images.len() - 1];
        verify_commit(commit, 11)?;
        assert_eq!(verify_commit(commit, 12), Err(FsError::Corrupt));
        assert_eq!(verify_commit(&images[0], 11), Err(FsError::Corrupt));

        let mut wrong_type = commit.clone();
        wrong_type[4..8].copy_from_slice(&(JBD2_COMMIT_BLOCK + 1).to_be_bytes());
        assert_eq!(verify_commit(&wrong_type, 11), Err(FsError::Corrupt));
        Ok(())
    }
}
