use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn executable_on_path(name: &OsStr) -> OsString {
    let Some(path) = env::var_os("PATH") else {
        return name.to_owned();
    };
    for directory in env::split_paths(&path) {
        let candidate = directory
            .join(name)
            .with_extension(env::consts::EXE_EXTENSION);
        if candidate.is_file() {
            return candidate.into_os_string();
        }
    }
    name.to_owned()
}

fn main() -> ExitCode {
    let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(repository) = manifest_directory
        .parent()
        .map(std::path::Path::to_path_buf)
    else {
        eprintln!("xtask must be inside the repository");
        return ExitCode::FAILURE;
    };
    let python = env::var_os("PYTHON")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            executable_on_path(OsStr::new(if cfg!(windows) { "python" } else { "python3" }))
        });

    match Command::new(python)
        .arg(repository.join("scripts/run-qemu.py"))
        .args(env::args_os().skip(1))
        .current_dir(repository)
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("failed to start the QEMU launcher: {error}");
            ExitCode::FAILURE
        }
    }
}
