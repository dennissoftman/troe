#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{
    CommandContext, FILESYSTEM_LIST_BUFFER_BYTES, INVOCATION_BUFFER_BYTES, entry, exit, filesystem,
};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() > 2 {
        return common::usage(&mut command.stderr(), "ls", b"ls [PATH]");
    }
    let path = invocation.argument(1).unwrap_or(".");
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let mut output = command.stdout();
    let mut cursor = 0_u64;
    let mut entries_seen = 0_usize;
    loop {
        let mut buffer = [0_u8; FILESYSTEM_LIST_BUFFER_BYTES];
        let page = match filesystem.list(
            path,
            cursor,
            filesystem::MAX_LIST_ENTRIES,
            filesystem::MAX_LIST_NAME_BYTES,
            &mut buffer,
        ) {
            Ok(page) => page,
            Err(error) => {
                return common::filesystem_failure(&mut command.stderr(), "ls", path, error);
            }
        };
        for entry in page.entries() {
            if output.write_all(entry.name.as_bytes()).is_err()
                || (entry.kind == filesystem::NodeKind::Directory
                    && output.write_all(b"/").is_err())
                || output.write_all(b"\n").is_err()
            {
                return common::stream_failure(&mut command.stderr(), "ls");
            }
            entries_seen += 1;
            if entries_seen > 1024 {
                return common::filesystem_failure(
                    &mut command.stderr(),
                    "ls",
                    path,
                    troe_kex_sdk::Error::NoSpace,
                );
            }
        }
        let Some(next) = page.next_cursor() else {
            return exit::SUCCESS;
        };
        if page.is_empty() && next == cursor {
            return exit::FAILURE;
        }
        cursor = next;
    }
}

entry!(main);
