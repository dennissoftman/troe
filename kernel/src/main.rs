//! UEFI-hosted Stage 1 image. The host fallback only explains how to build it.
#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]
#![forbid(unsafe_code)]

#[cfg(not(target_os = "uefi"))]
fn main() {
    println!("build with --target x86_64-unknown-uefi or aarch64-unknown-uefi");
}

#[cfg(target_os = "uefi")]
mod firmware {
    extern crate alloc;

    use alloc::borrow::Cow;
    use alloc::string::String;
    use core::fmt::Write as _;

    use kllm_core::{Input, MAX_LINE_BYTES, Output, StreamError, is_backspace};
    use kllm_shell::Shell;
    use kllm_vfs::{Namespace, RamFsQuota};
    use uefi::boot;
    use uefi::prelude::*;
    use uefi::proto::console::text::{Key, ScanCode};

    const ROOTFS: &[u8] = include_bytes!("../../assets/root.kefs");

    struct ConsoleOutput;

    impl Output for ConsoleOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            let succeeded = uefi::system::with_stdout(|stdout| {
                if bytes == b"\x1b[2J\x1b[H" {
                    stdout.clear().is_ok()
                } else {
                    let text = String::from_utf8_lossy(bytes);
                    stdout.write_str(text.as_ref()).is_ok()
                }
            });
            if succeeded {
                Ok(bytes.len())
            } else {
                Err(StreamError::Device)
            }
        }
    }

    struct EmptyInput;

    impl Input for EmptyInput {
        fn read(&mut self, _destination: &mut [u8]) -> Result<usize, StreamError> {
            Ok(0)
        }
    }

    #[entry]
    fn main() -> Status {
        if uefi::helpers::init().is_err() {
            return Status::DEVICE_ERROR;
        }
        let result = run();
        match result {
            Ok(()) => Status::SUCCESS,
            Err(()) => Status::ABORTED,
        }
    }

    fn run() -> Result<(), ()> {
        let mut console = ConsoleOutput;
        write_console(&mut console, b"kllm 0.1.0 UEFI hosted environment\n")?;
        write_console(
            &mut console,
            b"type 'help'; quoting and bounded pipelines are enabled\n",
        )?;

        let mut namespace = Namespace::new(RamFsQuota::default());
        namespace.mount_embedded(ROOTFS).map_err(|_| ())?;
        let mut shell = Shell::new(namespace, architecture(), true).map_err(|_| ())?;

        loop {
            write_console(&mut console, b"kllm:")?;
            write_console(&mut console, shell.cwd().as_bytes())?;
            write_console(&mut console, b"> ")?;
            let line = read_line(&mut console)?;
            let mut input = EmptyInput;
            let mut error = ConsoleOutput;
            let _status = shell.execute(line.as_ref(), &mut input, &mut console, &mut error);
            if shell.halt_requested() {
                write_console(&mut console, b"halting: returning control to firmware\n")?;
                return Ok(());
            }
        }
    }

    fn read_line(console: &mut ConsoleOutput) -> Result<Cow<'static, str>, ()> {
        let mut line = String::new();
        let mut overflow = false;
        loop {
            let key = wait_for_key()?;
            match key {
                Key::Printable(value) => match char::from(value) {
                    '\r' | '\n' => {
                        write_console(console, b"\n")?;
                        if overflow {
                            write_console(console, b"input: line exceeded 512 bytes; discarded\n")?;
                            line.clear();
                            overflow = false;
                            continue;
                        }
                        return Ok(Cow::Owned(line));
                    }
                    value if is_backspace(value) => {
                        erase_previous(&mut line, console)?;
                    }
                    value if !value.is_control() && !overflow => {
                        if line.len() + value.len_utf8() > MAX_LINE_BYTES {
                            overflow = true;
                        } else {
                            line.push(value);
                            let mut encoded = [0_u8; 4];
                            write_console(console, value.encode_utf8(&mut encoded).as_bytes())?;
                        }
                    }
                    _ => {}
                },
                // Some serial-backed UEFI consoles report the host Backspace
                // key through the DELETE scan code instead of Unicode BS/DEL.
                Key::Special(ScanCode::DELETE) => erase_previous(&mut line, console)?,
                Key::Special(_) => {}
            }
        }
    }

    fn erase_previous(line: &mut String, console: &mut ConsoleOutput) -> Result<(), ()> {
        if line.pop().is_some() {
            write_console(console, b"\x08 \x08")?;
        }
        Ok(())
    }

    fn wait_for_key() -> Result<Key, ()> {
        loop {
            let result = uefi::system::with_stdin(|stdin| {
                if let Some(key) = stdin.read_key()? {
                    return Ok(Some(key));
                }
                let mut events = [stdin.wait_for_key_event()?];
                if boot::wait_for_event(&mut events).is_err() {
                    return Err(Status::DEVICE_ERROR.into());
                }
                stdin.read_key()
            });
            match result {
                Ok(Some(key)) => return Ok(key),
                Ok(None) => {}
                _ => return Err(()),
            }
        }
    }

    fn write_console(console: &mut ConsoleOutput, bytes: &[u8]) -> Result<(), ()> {
        kllm_core::write_all(console, bytes).map_err(|_| ())
    }

    const fn architecture() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "x86_64"
        }
        #[cfg(target_arch = "aarch64")]
        {
            "aarch64"
        }
    }
}
