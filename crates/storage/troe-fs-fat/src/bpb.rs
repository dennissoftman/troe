//! The BIOS parameter block and the `FSInfo` sector.

use crate::{FAT32_MAX_CLUSTER, FAT32_MIN_CLUSTERS, read_u16, read_u32};
use troe_fs_api::FsError;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Bpb {
    pub(crate) sectors_per_cluster: u8,
    pub(crate) reserved_sectors: u16,
    pub(crate) fat_sectors: u32,
    pub(crate) root_cluster: u32,
    pub(crate) fsinfo_sector: u16,
    pub(crate) backup_sector: u16,
    pub(crate) data_start: u64,
    pub(crate) cluster_count: u32,
    pub(crate) media: u8,
    pub(crate) volume_id: u32,
}

pub(crate) fn parse_bpb(
    boot: &[u8],
    region_blocks: u64,
    block_bytes: usize,
) -> Result<Bpb, FsError> {
    if boot.len() != block_bytes
        || boot.len() < 512
        || !((boot[0] == 0xeb && boot[2] == 0x90) || boot[0] == 0xe9)
        || boot[510..512] != [0x55, 0xaa]
        || read_u16(boot, 11)? != u16::try_from(block_bytes).map_err(|_| FsError::Unsupported)?
        || !boot[13].is_power_of_two()
        || boot[13] == 0
        || read_u16(boot, 17)? != 0
        || read_u16(boot, 19)? != 0
        || read_u16(boot, 22)? != 0
        || boot[16] != 2
        || read_u16(boot, 40)? != 0
        || read_u16(boot, 42)? != 0
        || boot[52..64].iter().any(|byte| *byte != 0)
        || boot[66] != 0x29
        || boot.get(82..90) != Some(b"FAT32   ")
    {
        return Err(FsError::Unsupported);
    }
    let reserved_sectors = read_u16(boot, 14)?;
    let total_sectors = read_u32(boot, 32)?;
    let fat_sectors = read_u32(boot, 36)?;
    let root_cluster = read_u32(boot, 44)?;
    let fsinfo_sector = read_u16(boot, 48)?;
    let backup_sector = read_u16(boot, 50)?;
    if reserved_sectors < 8
        || total_sectors == 0
        || u64::from(total_sectors) != region_blocks
        || fat_sectors == 0
        || fsinfo_sector == 0
        || fsinfo_sector >= reserved_sectors
        || backup_sector == 0
        || backup_sector >= reserved_sectors
        || fsinfo_sector == backup_sector
    {
        return Err(FsError::Corrupt);
    }
    let fats_total = u64::from(fat_sectors)
        .checked_mul(2)
        .ok_or(FsError::Overflow)?;
    let data_start = u64::from(reserved_sectors)
        .checked_add(fats_total)
        .ok_or(FsError::Overflow)?;
    let data_sectors = u64::from(total_sectors)
        .checked_sub(data_start)
        .ok_or(FsError::Corrupt)?;
    let cluster_count_u64 = data_sectors / u64::from(boot[13]);
    let cluster_count = u32::try_from(cluster_count_u64).map_err(|_| FsError::Unsupported)?;
    let fat_entries = u64::from(fat_sectors)
        .checked_mul(u64::try_from(block_bytes).map_err(|_| FsError::Overflow)?)
        .ok_or(FsError::Overflow)?
        / 4;
    if !(FAT32_MIN_CLUSTERS..=FAT32_MAX_CLUSTER - 1).contains(&cluster_count)
        || fat_entries < u64::from(cluster_count) + 2
        || root_cluster < 2
        || root_cluster > cluster_count + 1
    {
        return Err(FsError::Unsupported);
    }
    Ok(Bpb {
        sectors_per_cluster: boot[13],
        reserved_sectors,
        fat_sectors,
        root_cluster,
        fsinfo_sector,
        backup_sector,
        data_start,
        cluster_count,
        media: boot[21],
        volume_id: read_u32(boot, 67)?,
    })
}

pub(crate) fn validate_fsinfo(bytes: &[u8], cluster_count: u32) -> Result<(), FsError> {
    if bytes.len() < 512
        || read_u32(bytes, 0)? != 0x4161_5252
        || read_u32(bytes, 484)? != 0x6141_7272
        || read_u32(bytes, 508)? != 0xaa55_0000
    {
        return Err(FsError::Corrupt);
    }
    let free = read_u32(bytes, 488)?;
    let next = read_u32(bytes, 492)?;
    if (free != u32::MAX && free > cluster_count)
        || (next != u32::MAX && !(2..=cluster_count + 1).contains(&next))
    {
        return Err(FsError::Corrupt);
    }
    Ok(())
}
