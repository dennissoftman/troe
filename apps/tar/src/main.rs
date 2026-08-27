#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::str;
use troe_app_tar::{
    BLOCK_BYTES, EntryKind, Header, MAX_MEMBER_BYTES, PaxMetadataValidator, decode_header,
    encode_header, padded_size,
};
use troe_kex_sdk::{
    CommandContext, Error, FILESYSTEM_IO_BUFFER_BYTES, FILESYSTEM_LIST_BUFFER_BYTES,
    FileReplacement, INVOCATION_BUFFER_BYTES, MAX_FILE_STREAM_CHUNK_BYTES, ReadOnlyFilesystem,
    entry, exit, filesystem,
};

const MAX_DEPTH: usize = 16;
const ZERO_BLOCK: [u8; BLOCK_BYTES] = [0; BLOCK_BYTES];

#[derive(Clone, Copy)]
struct PathBuffer {
    bytes: [u8; filesystem::MAX_PATH_BYTES],
    len: usize,
}

impl PathBuffer {
    fn absolute(cwd: &str, path: &str) -> Result<Self, ()> {
        let mut output = Self {
            bytes: [0; filesystem::MAX_PATH_BYTES],
            len: 1,
        };
        output.bytes[0] = b'/';
        if !path.starts_with('/') {
            output.extend_components(cwd)?;
        }
        output.extend_components(path)?;
        Ok(output)
    }

    fn member(path: &str) -> Result<Self, ()> {
        let mut output = Self {
            bytes: [0; filesystem::MAX_PATH_BYTES],
            len: 0,
        };
        for component in path.trim_start_matches('/').split('/') {
            if component.is_empty() || matches!(component, "." | "..") {
                return Err(());
            }
            output.push_component(component)?;
        }
        if output.len == 0 || output.len > MAX_MEMBER_BYTES {
            return Err(());
        }
        Ok(output)
    }

    fn extend_components(&mut self, path: &str) -> Result<(), ()> {
        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => self.pop_component(),
                value => self.push_component(value)?,
            }
        }
        Ok(())
    }

    fn push_component(&mut self, component: &str) -> Result<(), ()> {
        if component.is_empty() || component.as_bytes().contains(&0) {
            return Err(());
        }
        let slash = usize::from(self.len != 0 && self.bytes[self.len - 1] != b'/');
        let end = self
            .len
            .checked_add(slash)
            .and_then(|value| value.checked_add(component.len()))
            .ok_or(())?;
        if end > self.bytes.len() {
            return Err(());
        }
        if slash != 0 {
            self.bytes[self.len] = b'/';
            self.len += 1;
        }
        self.bytes[self.len..end].copy_from_slice(component.as_bytes());
        self.len = end;
        Ok(())
    }

    fn pop_component(&mut self) {
        if self.len <= 1 {
            self.len = usize::from(self.bytes.first() == Some(&b'/'));
            return;
        }
        self.len = self.bytes[..self.len]
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(0, |index| index.max(1));
    }

    fn joined(self, component: &str) -> Result<Self, ()> {
        let mut output = self;
        output.push_component(component)?;
        Ok(output)
    }

    fn as_str(&self) -> &str {
        str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

struct Scratch {
    io: [u8; FILESYSTEM_IO_BUFFER_BYTES],
    list: [u8; FILESYSTEM_LIST_BUFFER_BYTES],
    link: [u8; filesystem::MAX_LINK_BYTES],
    block: [u8; BLOCK_BYTES],
}

impl Scratch {
    const fn new() -> Self {
        Self {
            io: [0; FILESYSTEM_IO_BUFFER_BYTES],
            list: [0; FILESYSTEM_LIST_BUFFER_BYTES],
            link: [0; filesystem::MAX_LINK_BYTES],
            block: [0; BLOCK_BYTES],
        }
    }
}

struct ArchiveWriter {
    replacement: FileReplacement,
}

impl ArchiveWriter {
    fn header(
        &mut self,
        path: &str,
        kind: EntryKind,
        size: u64,
        link: &str,
        block: &mut [u8; BLOCK_BYTES],
    ) -> Result<(), Error> {
        encode_header(path, kind, size, link, block).map_err(|_| Error::InvalidPath)?;
        self.replacement.write_all(block)
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.replacement.write_all(bytes)
    }

    fn padding(&mut self, size: u64) -> Result<(), Error> {
        let padded = padded_size(size).map_err(|_| Error::Overflow)?;
        let count = usize::try_from(padded - size).map_err(|_| Error::Overflow)?;
        self.replacement.write_all(&ZERO_BLOCK[..count])
    }

    fn finish(mut self) -> Result<(), Error> {
        self.replacement.write_all(&ZERO_BLOCK)?;
        self.replacement.write_all(&ZERO_BLOCK)?;
        self.replacement.commit()
    }
}

struct ArchiveReader {
    file: filesystem::OpenFile,
    offset: u64,
}

impl ArchiveReader {
    fn new(filesystem: &mut ReadOnlyFilesystem, path: &str) -> Result<Self, Error> {
        let file = filesystem.open(path)?;
        Ok(Self { file, offset: 0 })
    }

    fn block(
        &mut self,
        filesystem: &mut ReadOnlyFilesystem,
        block: &mut [u8; BLOCK_BYTES],
    ) -> Result<(), Error> {
        self.read_exact(filesystem, block)
    }

    fn read_exact(
        &mut self,
        filesystem: &mut ReadOnlyFilesystem,
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        while !output.is_empty() {
            let count = filesystem.read(self.file, self.offset, output)?;
            if count == 0 || count > output.len() {
                return Err(Error::Corrupt);
            }
            self.offset = self
                .offset
                .checked_add(count as u64)
                .ok_or(Error::Overflow)?;
            output = &mut output[count..];
        }
        Ok(())
    }

    fn skip(&mut self, bytes: u64) -> Result<(), Error> {
        let next = self.offset.checked_add(bytes).ok_or(Error::Overflow)?;
        if next > self.file.byte_count {
            return Err(Error::Corrupt);
        }
        self.offset = next;
        Ok(())
    }

    fn close(self, filesystem: &mut ReadOnlyFilesystem) -> Result<(), Error> {
        filesystem.close(self.file)
    }
}

fn add_path(
    filesystem: &mut ReadOnlyFilesystem,
    writer: &mut ArchiveWriter,
    source: PathBuffer,
    member: PathBuffer,
    archive_path: &str,
    depth: usize,
    scratch: &mut Scratch,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::TooLarge);
    }
    if source.as_str() == archive_path {
        return Ok(());
    }

    match filesystem.read_link(source.as_str(), &mut scratch.link) {
        Ok(target) => {
            writer.header(
                member.as_str(),
                EntryKind::Symlink,
                0,
                target,
                &mut scratch.block,
            )?;
            return Ok(());
        }
        Err(Error::WrongType | Error::Unsupported) => {}
        Err(error) => return Err(error),
    }

    let metadata = filesystem.metadata(source.as_str())?;
    match metadata.kind {
        filesystem::NodeKind::File => {
            writer.header(
                member.as_str(),
                EntryKind::File,
                metadata.byte_count,
                "",
                &mut scratch.block,
            )?;
            let file = filesystem.open(source.as_str())?;
            let transfer = (|| {
                let mut offset = 0_u64;
                while offset < file.byte_count {
                    let remaining = usize::try_from(file.byte_count - offset)
                        .unwrap_or(usize::MAX)
                        .min(scratch.io.len());
                    let count = filesystem.read(file, offset, &mut scratch.io[..remaining])?;
                    if count == 0 || count > remaining {
                        return Err(Error::Corrupt);
                    }
                    writer.bytes(&scratch.io[..count])?;
                    offset = offset.checked_add(count as u64).ok_or(Error::Overflow)?;
                }
                if offset != metadata.byte_count {
                    return Err(Error::Corrupt);
                }
                Ok(())
            })();
            let close = filesystem.close(file);
            transfer?;
            close?;
            writer.padding(metadata.byte_count)
        }
        filesystem::NodeKind::Directory => {
            writer.header(
                member.as_str(),
                EntryKind::Directory,
                0,
                "",
                &mut scratch.block,
            )?;
            let mut cursor = 0_u64;
            loop {
                let page = filesystem.list(source.as_str(), cursor, 1, 64, &mut scratch.list)?;
                let next = page.next_cursor();
                let mut child_name = [0_u8; 64];
                let child_len = match page.entries().next() {
                    Some(entry) => {
                        child_name[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
                        entry.name.len()
                    }
                    None if next.is_none() => break,
                    None => return Err(Error::Corrupt),
                };
                let name = str::from_utf8(&child_name[..child_len]).map_err(|_| Error::Corrupt)?;
                let child_source = source.joined(name).map_err(|_| Error::TooLarge)?;
                let child_member = member.joined(name).map_err(|_| Error::TooLarge)?;
                add_path(
                    filesystem,
                    writer,
                    child_source,
                    child_member,
                    archive_path,
                    depth + 1,
                    scratch,
                )?;
                match next {
                    Some(value) if value != cursor => cursor = value,
                    Some(_) => return Err(Error::Corrupt),
                    None => break,
                }
            }
            Ok(())
        }
        filesystem::NodeKind::Symlink => Err(Error::Corrupt),
    }
}

fn safe_existing_directory(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut troe_kex_sdk::FilesystemMutation,
    path: &str,
    link_buffer: &mut [u8; filesystem::MAX_LINK_BYTES],
) -> Result<(), Error> {
    match filesystem.read_link(path, link_buffer) {
        Ok(_) => return Err(Error::InvalidPath),
        Err(Error::WrongType | Error::Unsupported | Error::NotFound) => {}
        Err(error) => return Err(error),
    }
    match filesystem.metadata(path) {
        Ok(metadata) if metadata.kind == filesystem::NodeKind::Directory => Ok(()),
        Ok(_) => Err(Error::WrongType),
        Err(Error::NotFound) => match mutation.create_directory(path) {
            Ok(()) | Err(Error::Exists) => Ok(()),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

fn ensure_parents(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut troe_kex_sdk::FilesystemMutation,
    path: &str,
    link_buffer: &mut [u8; filesystem::MAX_LINK_BYTES],
) -> Result<(), Error> {
    for (index, byte) in path.as_bytes().iter().copied().enumerate() {
        if byte == b'/' {
            safe_existing_directory(filesystem, mutation, &path[..index], link_buffer)?;
        }
    }
    Ok(())
}

fn reject_existing_symlink(
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    link_buffer: &mut [u8; filesystem::MAX_LINK_BYTES],
) -> Result<(), Error> {
    match filesystem.read_link(path, link_buffer) {
        Ok(_) => Err(Error::InvalidPath),
        Err(Error::WrongType | Error::Unsupported | Error::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

fn extract_entry(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut troe_kex_sdk::FilesystemMutation,
    reader: &mut ArchiveReader,
    header: Header,
    scratch: &mut Scratch,
) -> Result<(), Error> {
    let path = header.path();
    ensure_parents(filesystem, mutation, path, &mut scratch.link)?;
    match header.kind {
        EntryKind::Directory => {
            safe_existing_directory(filesystem, mutation, path, &mut scratch.link)
        }
        EntryKind::Symlink => {
            reject_existing_symlink(filesystem, path, &mut scratch.link)?;
            mutation.create_symlink(header.link(), path)
        }
        EntryKind::File => {
            reject_existing_symlink(filesystem, path, &mut scratch.link)?;
            let mut replacement = mutation.begin_replace(path)?;
            replacement.set_chunk_size(MAX_FILE_STREAM_CHUNK_BYTES)?;
            let mut remaining = header.size;
            while remaining != 0 {
                let count = scratch
                    .io
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                reader.read_exact(filesystem, &mut scratch.io[..count])?;
                replacement.write_all(&scratch.io[..count])?;
                remaining -= count as u64;
            }
            let padding = padded_size(header.size).map_err(|_| Error::Overflow)? - header.size;
            reader.skip(padding)?;
            replacement.commit()
        }
        EntryKind::Extended => Err(Error::Corrupt),
    }
}

fn consume_extended_header(
    filesystem: &mut ReadOnlyFilesystem,
    reader: &mut ArchiveReader,
    size: u64,
    scratch: &mut Scratch,
) -> Result<(), Error> {
    let mut validator = PaxMetadataValidator::new();
    let mut remaining = size;
    while remaining != 0 {
        let count = scratch
            .io
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        reader.read_exact(filesystem, &mut scratch.io[..count])?;
        validator
            .push(&scratch.io[..count])
            .map_err(|_| Error::Corrupt)?;
        remaining -= count as u64;
    }
    validator.finish().map_err(|_| Error::Corrupt)?;
    let padding = padded_size(size).map_err(|_| Error::Overflow)? - size;
    reader.skip(padding)
}

fn create<'operand>(
    command: &mut CommandContext,
    archive: &str,
    operands: impl Iterator<Item = &'operand str>,
) -> Result<(), Error> {
    if archive == "-" {
        return Err(Error::TooLarge);
    }
    let mut filesystem = command.filesystem()?;
    let mut mutation = command.filesystem_mutation()?;
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let invocation = command
        .invocation(&mut invocation_bytes)
        .map_err(|_| Error::InvalidCall)?;
    let archive_path =
        PathBuffer::absolute(invocation.cwd(), archive).map_err(|_| Error::InvalidPath)?;
    let mut link_buffer = [0_u8; filesystem::MAX_LINK_BYTES];
    reject_existing_symlink(&mut filesystem, archive_path.as_str(), &mut link_buffer)?;
    let mut replacement = mutation.begin_replace(archive_path.as_str())?;
    replacement.set_chunk_size(MAX_FILE_STREAM_CHUNK_BYTES)?;
    let mut writer = ArchiveWriter { replacement };
    let mut scratch = Scratch::new();
    for operand in operands {
        let source =
            PathBuffer::absolute(invocation.cwd(), operand).map_err(|_| Error::InvalidPath)?;
        let member = PathBuffer::member(operand).map_err(|_| Error::InvalidPath)?;
        add_path(
            &mut filesystem,
            &mut writer,
            source,
            member,
            archive_path.as_str(),
            0,
            &mut scratch,
        )?;
    }
    writer.finish()
}

fn read_archive(command: &mut CommandContext, archive: &str, extract: bool) -> Result<(), Error> {
    if archive == "-" {
        return Err(Error::TooLarge);
    }
    let mut filesystem = command.filesystem()?;
    let mut mutation = if extract {
        Some(command.filesystem_mutation()?)
    } else {
        None
    };
    let mut reader = ArchiveReader::new(&mut filesystem, archive)?;
    let mut scratch = Scratch::new();
    loop {
        reader.block(&mut filesystem, &mut scratch.block)?;
        match decode_header(&scratch.block).map_err(|_| Error::Corrupt)? {
            None => {
                reader.block(&mut filesystem, &mut scratch.block)?;
                if scratch.block.iter().any(|byte| *byte != 0) {
                    return Err(Error::Corrupt);
                }
                break;
            }
            Some(header) if header.kind == EntryKind::Extended => {
                consume_extended_header(&mut filesystem, &mut reader, header.size, &mut scratch)?
            }
            Some(header) if extract => extract_entry(
                &mut filesystem,
                mutation.as_mut().ok_or(Error::MissingAuthority)?,
                &mut reader,
                header,
                &mut scratch,
            )?,
            Some(header) => {
                command.stdout().write_all(header.path().as_bytes())?;
                command.stdout().write_all(b"\n")?;
                reader.skip(padded_size(header.size).map_err(|_| Error::Overflow)?)?;
            }
        }
    }
    reader.close(&mut filesystem)
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(options) = invocation.argument(1) else {
        return common::usage(
            &mut command.stderr(),
            "tar",
            b"tar -cf ARCHIVE PATH... | tar -tf ARCHIVE | tar -xf ARCHIVE",
        );
    };
    let options = options.strip_prefix('-').unwrap_or(options);
    let Some(archive) = invocation.argument(2) else {
        return common::usage(
            &mut command.stderr(),
            "tar",
            b"tar -cf ARCHIVE PATH... | tar -tf ARCHIVE | tar -xf ARCHIVE",
        );
    };
    let result = match options {
        "cf" if invocation.len() >= 4 => create(
            command,
            archive,
            (3..invocation.len()).filter_map(|index| invocation.argument(index)),
        ),
        "tf" if invocation.len() == 3 => read_archive(command, archive, false),
        "xf" if invocation.len() == 3 => read_archive(command, archive, true),
        _ => {
            return common::usage(
                &mut command.stderr(),
                "tar",
                b"tar -cf ARCHIVE PATH... | tar -tf ARCHIVE | tar -xf ARCHIVE",
            );
        }
    };
    match result {
        Ok(()) => exit::SUCCESS,
        Err(error) => common::filesystem_failure(&mut command.stderr(), "tar", archive, error),
    }
}

entry!(main);
