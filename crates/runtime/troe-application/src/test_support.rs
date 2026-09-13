//! Static-TLS artifact fixtures shared by portable placement/ownership tests.
use crate::{
    KEX_V1_LOAD_RECORD_BYTES, KEX_V1_MAGIC, PAGE_SIZE, Target,
    bytes::{write_u16, write_u32, write_u64},
    canonical_image_span_bytes,
    tls_artifact::{HEADER_BYTES, Metadata},
};
use alloc::{vec, vec::Vec};

pub(crate) struct TlsFixture {
    pub(crate) heap: u64,
    pub(crate) stack: u64,
    pub(crate) file: usize,
    pub(crate) memory: u64,
    pub(crate) alignment: u64,
    pub(crate) segments: usize,
    pub(crate) gap: u64,
}
impl Default for TlsFixture {
    fn default() -> Self {
        Self {
            heap: 3,
            stack: 4,
            file: 3,
            memory: 37,
            alignment: 64,
            segments: 2,
            gap: 0,
        }
    }
}
impl TlsFixture {
    pub(crate) fn encode(&self, target: Target) -> Vec<u8> {
        let payload = HEADER_BYTES + self.segments * KEX_V1_LOAD_RECORD_BYTES;
        let file_offset = payload + 16 + self.file;
        let mut bytes = vec![0; file_offset + self.file];
        bytes[..8].copy_from_slice(&KEX_V1_MAGIC);
        for (offset, value) in [
            (8, 1),
            (10, 3),
            (12, target as u16),
            (14, 160),
            (16, 40),
            (18, 1),
            (20, 4),
            (22, 2),
            (
                32,
                u16::try_from(self.segments).unwrap_or_else(|_| unreachable!()),
            ),
            (72, 16),
        ] {
            write_u16(&mut bytes, offset, value);
        }
        for (offset, value) in [(56, HEADER_BYTES), (60, payload), (64, payload)] {
            write_u32(
                &mut bytes,
                offset,
                u32::try_from(value).unwrap_or_else(|_| unreachable!()),
            );
        }
        write_u64(&mut bytes, 40, self.stack);
        write_u64(&mut bytes, 48, self.heap);
        write_u64(&mut bytes, 80, (file_offset + self.file) as u64);
        let mut image_end = 0;
        let mut source = 0;
        let mut file_at = payload;
        for index in 0..self.segments {
            let at = HEADER_BYTES + index * KEX_V1_LOAD_RECORD_BYTES;
            let offset = if index == 0 { 0 } else { image_end + self.gap };
            let file = match index {
                0 => 16,
                1 => self.file,
                _ => 0,
            };
            let memory = (file as u64).div_ceil(PAGE_SIZE).max(1) * PAGE_SIZE;
            for (field, value) in [
                (0, offset),
                (8, file_at as u64),
                (16, file as u64),
                (24, memory),
            ] {
                write_u64(&mut bytes, at + field, value);
            }
            write_u32(
                &mut bytes,
                at + 32,
                match index {
                    0 => 2,
                    1 => 3,
                    _ => 1,
                },
            );
            if index == 1 {
                source = offset;
            }
            bytes[file_at..file_at + file].fill(if index == 0 { 0x90 } else { 0x5a });
            image_end = offset + memory;
            file_at += file;
        }
        let span = canonical_image_span_bytes(image_end).unwrap_or_else(|| unreachable!());
        write_u32(
            &mut bytes,
            36,
            u32::try_from(span / PAGE_SIZE).unwrap_or_else(|_| unreachable!()),
        );
        bytes[file_offset..].fill(0x5a);
        let extension = Metadata {
            source_offset: if self.file == 0 { 0 } else { source },
            file_offset: file_offset as u64,
            file_bytes: self.file as u64,
            memory_bytes: self.memory,
            alignment: self.alignment,
            trampoline_offset: 4,
        }
        .encode(target)
        .unwrap_or_else(|_| unreachable!());
        bytes[96..HEADER_BYTES].copy_from_slice(&extension);
        bytes
    }
}
