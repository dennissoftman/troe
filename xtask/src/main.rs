use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

const DEFAULT_PLATFORM: &str = "x86_64-q35-uefi";
const DEFAULT_ENVIRONMENT: &str = "qemu";

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

fn has_option(arguments: &[OsString], name: &str) -> bool {
    let assignment = format!("{name}=");
    arguments.iter().any(|argument| {
        argument == OsStr::new(name)
            || argument
                .to_str()
                .is_some_and(|argument| argument.starts_with(&assignment))
    })
}

fn with_interactive_defaults(arguments: Vec<OsString>) -> (Vec<OsString>, bool) {
    let default_platform = !has_option(&arguments, "--platform");
    let default_environment = !has_option(&arguments, "--environment");
    if !default_platform && !default_environment {
        return (arguments, false);
    }
    let mut resolved = Vec::with_capacity(arguments.len() + 4);
    if default_platform {
        resolved.push(OsString::from("--platform"));
        resolved.push(OsString::from(DEFAULT_PLATFORM));
    }
    if default_environment {
        resolved.push(OsString::from("--environment"));
        resolved.push(OsString::from(DEFAULT_ENVIRONMENT));
    }
    resolved.extend(arguments);
    (resolved, true)
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

    let (arguments, defaulted) = with_interactive_defaults(env::args_os().skip(1).collect());
    if defaulted {
        eprintln!(
            "cargo qemu: default platform={DEFAULT_PLATFORM} environment={DEFAULT_ENVIRONMENT}"
        );
    }

    match Command::new(python)
        .arg(repository.join("scripts/run-qemu.py"))
        .args(arguments)
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

#[cfg(test)]
mod tests {
    use super::{DEFAULT_ENVIRONMENT, DEFAULT_PLATFORM, with_interactive_defaults};
    use std::ffi::OsString;

    #[test]
    fn empty_invocation_selects_one_named_interactive_default() {
        let (arguments, defaulted) = with_interactive_defaults(Vec::new());
        assert!(defaulted);
        assert_eq!(
            arguments,
            [
                OsString::from("--platform"),
                OsString::from(DEFAULT_PLATFORM),
                OsString::from("--environment"),
                OsString::from(DEFAULT_ENVIRONMENT),
            ]
        );
    }

    #[test]
    fn explicit_selection_is_preserved_and_partial_selection_is_completed() {
        let explicit = vec![
            OsString::from("--platform=aarch64-virt-uefi"),
            OsString::from("--environment"),
            OsString::from("qemu"),
            OsString::from("--graphical"),
        ];
        let (arguments, defaulted) = with_interactive_defaults(explicit.clone());
        assert!(!defaulted);
        assert_eq!(arguments, explicit);

        let (arguments, defaulted) =
            with_interactive_defaults(vec![OsString::from("--platform=aarch64-virt-uefi")]);
        assert!(defaulted);
        assert_eq!(arguments[0], OsString::from("--environment"));
        assert_eq!(arguments[1], OsString::from(DEFAULT_ENVIRONMENT));
    }
}
