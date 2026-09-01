use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

const DEFAULT_ENVIRONMENT: &str = "qemu";
const X86_64_PLATFORM: &str = "x86_64-q35-uefi";
const AARCH64_PLATFORM: &str = "aarch64-sbsa-ref";
const ALPINE_COMMAND: &str = "alpine";
const MOUNT_COMMAND: &str = "mount";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tool {
    Qemu,
    Alpine,
    Mount,
}

fn select_tool(arguments: Vec<OsString>) -> (Tool, Vec<OsString>) {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some(ALPINE_COMMAND) => (Tool::Alpine, arguments.into_iter().skip(1).collect()),
        Some(MOUNT_COMMAND) => (Tool::Mount, arguments.into_iter().skip(1).collect()),
        _ => (Tool::Qemu, arguments),
    }
}

fn default_platform(host_architecture: &str) -> Option<&'static str> {
    match host_architecture {
        "x86_64" => Some(X86_64_PLATFORM),
        "aarch64" => Some(AARCH64_PLATFORM),
        _ => None,
    }
}

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

fn with_interactive_defaults(
    arguments: Vec<OsString>,
    host_architecture: &str,
) -> Result<(Vec<OsString>, bool), String> {
    let use_default_platform = !has_option(&arguments, "--platform");
    let default_environment = !has_option(&arguments, "--environment");
    if !use_default_platform && !default_environment {
        return Ok((arguments, false));
    }
    let mut resolved = Vec::with_capacity(arguments.len() + 4);
    if use_default_platform {
        let platform = default_platform(host_architecture).ok_or_else(|| {
            format!(
                "cannot select a native QEMU platform for unsupported host architecture {host_architecture:?}; pass --platform explicitly"
            )
        })?;
        resolved.push(OsString::from("--platform"));
        resolved.push(OsString::from(platform));
    }
    if default_environment {
        resolved.push(OsString::from("--environment"));
        resolved.push(OsString::from(DEFAULT_ENVIRONMENT));
    }
    resolved.extend(arguments);
    Ok((resolved, true))
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

    let (tool, arguments) = select_tool(env::args_os().skip(1).collect());
    let (script, arguments, command_name) = match tool {
        Tool::Mount => (
            repository.join("tools/mount_shared.py"),
            arguments,
            tool.command_name(),
        ),
        Tool::Qemu | Tool::Alpine => {
            let host_architecture = env::consts::ARCH;
            let (arguments, defaulted) =
                match with_interactive_defaults(arguments, host_architecture) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        eprintln!("cargo {}: {error}", tool.command_name());
                        return ExitCode::FAILURE;
                    }
                };
            if defaulted {
                eprintln!(
                    "cargo {}: using host architecture {host_architecture} for omitted defaults",
                    tool.command_name()
                );
            }
            let script = match tool {
                Tool::Qemu => repository.join("scripts/run-qemu.py"),
                Tool::Alpine => repository.join("scripts/run-alpine.py"),
                Tool::Mount => unreachable!(),
            };
            (script, arguments, tool.command_name())
        }
    };

    match Command::new(python)
        .arg(script)
        .args(arguments)
        .current_dir(repository)
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("failed to start cargo {command_name}: {error}");
            ExitCode::FAILURE
        }
    }
}

impl Tool {
    const fn command_name(self) -> &'static str {
        match self {
            Self::Qemu => "qemu",
            Self::Alpine => "alpine",
            Self::Mount => "mount",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AARCH64_PLATFORM, DEFAULT_ENVIRONMENT, Tool, X86_64_PLATFORM, default_platform,
        select_tool, with_interactive_defaults,
    };
    use std::ffi::OsString;

    #[test]
    fn empty_invocation_selects_aarch64_default_on_aarch64_hosts() {
        let (arguments, defaulted) = with_interactive_defaults(Vec::new(), "aarch64").unwrap();
        assert!(defaulted);
        assert_eq!(
            arguments,
            [
                OsString::from("--platform"),
                OsString::from(AARCH64_PLATFORM),
                OsString::from("--environment"),
                OsString::from(DEFAULT_ENVIRONMENT),
            ]
        );
    }

    #[test]
    fn platform_default_follows_supported_host_architectures() {
        assert_eq!(default_platform("x86_64"), Some(X86_64_PLATFORM));
        assert_eq!(default_platform("aarch64"), Some(AARCH64_PLATFORM));
        assert_eq!(default_platform("riscv64"), None);
    }

    #[test]
    fn explicit_selection_is_preserved_and_partial_selection_is_completed() {
        let explicit = vec![
            OsString::from("--platform=aarch64-sbsa-ref"),
            OsString::from("--environment"),
            OsString::from("qemu"),
            OsString::from("--graphical"),
        ];
        let (arguments, defaulted) =
            with_interactive_defaults(explicit.clone(), "unsupported").unwrap();
        assert!(!defaulted);
        assert_eq!(arguments, explicit);

        let (arguments, defaulted) = with_interactive_defaults(
            vec![OsString::from("--platform=aarch64-sbsa-ref")],
            "unsupported",
        )
        .unwrap();
        assert!(defaulted);
        assert_eq!(arguments[0], OsString::from("--environment"));
        assert_eq!(arguments[1], OsString::from(DEFAULT_ENVIRONMENT));
    }

    #[test]
    fn unsupported_host_requires_an_explicit_platform() {
        let error = with_interactive_defaults(Vec::new(), "riscv64").unwrap_err();
        assert!(error.contains("unsupported host architecture \"riscv64\""));
        assert!(error.contains("pass --platform explicitly"));
    }

    #[test]
    fn mount_subcommand_is_removed_before_python_dispatch() {
        let (tool, arguments) =
            select_tool(vec![OsString::from("mount"), OsString::from("--read-only")]);
        assert_eq!(tool, Tool::Mount);
        assert_eq!(arguments, [OsString::from("--read-only")]);

        let (tool, arguments) = select_tool(vec![OsString::from("--dry-run")]);
        assert_eq!(tool, Tool::Qemu);
        assert_eq!(arguments, [OsString::from("--dry-run")]);
    }

    #[test]
    fn alpine_subcommand_is_removed_before_python_dispatch() {
        let (tool, arguments) = select_tool(vec![
            OsString::from("alpine"),
            OsString::from("--platform"),
            OsString::from(AARCH64_PLATFORM),
        ]);
        assert_eq!(tool, Tool::Alpine);
        assert_eq!(
            arguments,
            [
                OsString::from("--platform"),
                OsString::from(AARCH64_PLATFORM)
            ]
        );
    }
}
