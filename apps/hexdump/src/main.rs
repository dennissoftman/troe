#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, StandardOutput, entry, exit};

const HEX: &[u8; 16] = b"0123456789abcdef";

struct Hexdump {
    row: [u8; 16],
    row_bytes: usize,
    offset: u64,
    output: StandardOutput,
}

impl Hexdump {
    fn new(output: StandardOutput) -> Self {
        Self {
            row: [0; 16],
            row_bytes: 0,
            offset: 0,
            output,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), ()> {
        for byte in bytes {
            self.row[self.row_bytes] = *byte;
            self.row_bytes += 1;
            if self.row_bytes == self.row.len() {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ()> {
        if self.row_bytes != 0 {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ()> {
        let mut line = [b' '; 64];
        let offset = u32::try_from(self.offset).map_err(|_| ())?.to_be_bytes();
        line[0] = HEX[usize::from(offset[0] >> 4)];
        line[1] = HEX[usize::from(offset[0] & 0xf)];
        line[2] = HEX[usize::from(offset[1] >> 4)];
        line[3] = HEX[usize::from(offset[1] & 0xf)];
        line[4] = HEX[usize::from(offset[2] >> 4)];
        line[5] = HEX[usize::from(offset[2] & 0xf)];
        line[6] = HEX[usize::from(offset[3] >> 4)];
        line[7] = HEX[usize::from(offset[3] & 0xf)];
        let mut cursor = 10;
        for byte in &self.row[..self.row_bytes] {
            line[cursor] = HEX[usize::from(*byte >> 4)];
            line[cursor + 1] = HEX[usize::from(*byte & 0xf)];
            line[cursor + 2] = b' ';
            cursor += 3;
        }
        line[cursor] = b'\n';
        cursor += 1;
        self.output.write_all(&line[..cursor]).map_err(|_| ())?;
        self.offset = self.offset.checked_add(self.row_bytes as u64).ok_or(())?;
        self.row_bytes = 0;
        Ok(())
    }
}

fn dump_input(command: &mut CommandContext) -> u32 {
    let mut input = command.stdin();
    let mut dump = Hexdump::new(command.stdout());
    let mut buffer = [0_u8; 512];
    loop {
        let count = match input.read(&mut buffer) {
            Ok(count) => count,
            Err(error) => {
                return common::stream_read_failure(&mut command.stderr(), "hexdump", error);
            }
        };
        if count == 0 {
            return if dump.finish().is_ok() {
                exit::SUCCESS
            } else {
                common::stream_failure(&mut command.stderr(), "hexdump")
            };
        }
        if dump.feed(&buffer[..count]).is_err() {
            return common::stream_failure(&mut command.stderr(), "hexdump");
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() > 2 {
        return common::usage(&mut command.stderr(), "hexdump", b"hexdump [FILE]");
    }
    let Some(path) = invocation.argument(1) else {
        return dump_input(command);
    };
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let file = match filesystem.open(path) {
        Ok(file) if file.byte_count <= common::COMMAND_BYTES => file,
        Ok(file) => {
            let _ignored = filesystem.close(file);
            return common::filesystem_failure(
                &mut command.stderr(),
                "hexdump",
                path,
                Error::NoSpace,
            );
        }
        Err(error) => {
            return common::filesystem_failure(&mut command.stderr(), "hexdump", path, error);
        }
    };
    let mut dump = Hexdump::new(command.stdout());
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 512];
    while offset < file.byte_count {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(
                    &mut command.stderr(),
                    "hexdump",
                    path,
                    Error::Corrupt,
                );
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(&mut command.stderr(), "hexdump", path, error);
            }
        };
        if dump.feed(&buffer[..count]).is_err() {
            let _ignored = filesystem.close(file);
            return common::stream_failure(&mut command.stderr(), "hexdump");
        }
        let Some(next) = offset.checked_add(count as u64) else {
            return exit::FAILURE;
        };
        offset = next;
    }
    if dump.finish().is_err() {
        let _ignored = filesystem.close(file);
        return common::stream_failure(&mut command.stderr(), "hexdump");
    }
    if filesystem.close(file).is_err() {
        return common::filesystem_failure(&mut command.stderr(), "hexdump", path, Error::Corrupt);
    }
    exit::SUCCESS
}

entry!(main);
