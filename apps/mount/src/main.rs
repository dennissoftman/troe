#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::Write as _;
use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, entry, exit, volume_control};

fn filesystem_name(filesystem: volume_control::Filesystem) -> &'static str {
    match filesystem {
        volume_control::Filesystem::Fat32 => "fat32",
        volume_control::Filesystem::Ext4V1 => "ext4-v1",
    }
}

fn access_name(access: volume_control::Access) -> &'static str {
    match access {
        volume_control::Access::ReadOnly => "ro",
        volume_control::Access::ReadWrite => "rw",
    }
}

fn activation_name(activation: volume_control::Activation) -> &'static str {
    match activation {
        volume_control::Activation::Auto => "auto",
        volume_control::Activation::Manual => "manual",
    }
}

fn state_name(state: volume_control::State) -> &'static str {
    match state {
        volume_control::State::Unavailable => "unavailable",
        volume_control::State::Ready => "ready",
        volume_control::State::Mounted => "mounted",
        volume_control::State::Failed => "failed",
    }
}

fn mount_failure(command: &mut CommandContext, name: &str, error: Error) -> u32 {
    let message = match error {
        Error::NotFound => b"not configured or matching media is unavailable".as_slice(),
        Error::Conflict => b"volume activation conflicts with current state".as_slice(),
        Error::Corrupt => b"prepared volume state is corrupt".as_slice(),
        Error::InvalidRequest | Error::InvalidPath => b"invalid volume name".as_slice(),
        _ => b"volume activation failed".as_slice(),
    };
    common::report_path(&mut command.stderr(), "mount", name, message);
    if error == Error::NotFound {
        exit::NOT_FOUND
    } else {
        exit::FAILURE
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() > 2 {
        return common::usage(&mut command.stderr(), "mount", b"mount [VOLUME]");
    }
    let Ok(mut volumes) = command.volume_control() else {
        return exit::DENIED;
    };
    if let Some(name) = invocation.argument(1) {
        return match volumes.activate(name) {
            Ok(()) => exit::SUCCESS,
            Err(error) => mount_failure(command, name, error),
        };
    }

    let mut buffer = [0_u8; volume_control::MAX_LIST_REPLY_BYTES];
    let list = match volumes.list(&mut buffer) {
        Ok(list) => list,
        Err(_) => {
            common::report(
                &mut command.stderr(),
                "mount",
                b"cannot list configured volumes",
            );
            return exit::FAILURE;
        }
    };
    let mut output = common::OutputWriter(&mut command.stdout());
    for volume in list.iter() {
        if writeln!(
            output,
            "{} /vol/{} {} {} {} {}",
            volume.name,
            volume.name,
            filesystem_name(volume.filesystem),
            access_name(volume.access),
            activation_name(volume.activation),
            state_name(volume.state),
        )
        .is_err()
        {
            return common::stream_failure(&mut command.stderr(), "mount");
        }
    }
    exit::SUCCESS
}

entry!(main);
