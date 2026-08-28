//! Immutable launch-environment helpers.

use troe_kex_sdk::command;

/// Conventional immutable values supplied when a launch has no explicit entry.
pub const DEFAULT_ENTRIES: [&str; 6] = [
    "HOME=/",
    "PATH=/bin",
    "TMPDIR=/tmp",
    "SHELL=/bin/sh",
    "USER=root",
    "LOGNAME=root",
];

/// Environment construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A name or current directory cannot be represented.
    InvalidValue,
    /// The caller-provided output table is too small.
    TooManyEntries,
}

fn split(entry: &str) -> Option<(&str, &str)> {
    let (name, value) = entry.split_once('=')?;
    (!name.is_empty()).then_some((name, value))
}

/// Look up one immutable value, applying TROE's conventional defaults.
#[must_use]
pub fn get<'a>(environment: command::Environment<'a>, cwd: &'a str, name: &str) -> Option<&'a str> {
    if name.is_empty() || name.as_bytes().contains(&b'=') {
        return None;
    }
    if name == "PWD" {
        return Some(cwd);
    }
    for entry in environment.iter() {
        let Some((candidate, value)) = split(entry) else {
            continue;
        };
        if candidate == name {
            return Some(value);
        }
    }
    for entry in DEFAULT_ENTRIES {
        let Some((candidate, value)) = split(entry) else {
            continue;
        };
        if candidate == name {
            return Some(value);
        }
    }
    None
}

/// Build the immutable environment inherited by a direct child launch.
///
/// Explicit entries retain launch order. Conventional defaults fill only
/// missing names, and `PWD` always reflects `cwd`.
///
/// # Errors
///
/// Rejects invalid current directories or insufficient caller storage.
pub fn child_entries<'a>(
    environment: command::Environment<'a>,
    cwd: &'a str,
    pwd_storage: &'a mut [u8],
    output: &mut [&'a str],
) -> Result<usize, Error> {
    if cwd.is_empty() || cwd.as_bytes().contains(&0) {
        return Err(Error::InvalidValue);
    }
    if pwd_storage.len() < 4 + cwd.len() {
        return Err(Error::TooManyEntries);
    }
    let mut count = 0_usize;
    for entry in environment.iter() {
        let Some((name, _)) = split(entry) else {
            return Err(Error::InvalidValue);
        };
        if name != "PWD" {
            if count == output.len() {
                return Err(Error::TooManyEntries);
            }
            output[count] = entry;
            count += 1;
        }
    }
    for default in DEFAULT_ENTRIES {
        let Some((name, _)) = split(default) else {
            return Err(Error::InvalidValue);
        };
        let exists = output[..count]
            .iter()
            .any(|entry| split(entry).is_some_and(|(candidate, _)| candidate == name));
        if !exists {
            if count == output.len() {
                return Err(Error::TooManyEntries);
            }
            output[count] = default;
            count += 1;
        }
    }
    pwd_storage[..4].copy_from_slice(b"PWD=");
    pwd_storage[4..4 + cwd.len()].copy_from_slice(cwd.as_bytes());
    if count == output.len() {
        return Err(Error::TooManyEntries);
    }
    output[count] =
        core::str::from_utf8(&pwd_storage[..4 + cwd.len()]).map_err(|_| Error::InvalidValue)?;
    count += 1;
    Ok(count)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{child_entries, get};
    use troe_kex_sdk::command;

    #[test]
    fn defaults_and_explicit_entries_are_bounded_and_inherited() {
        let mut encoded = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let count = command::encode_environment(&["HOME=/custom", "LANG=C"], &mut encoded)
            .unwrap_or_else(|_| std::process::abort());
        let environment = command::Environment::parse(&encoded[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(get(environment, "/work", "HOME"), Some("/custom"));
        assert_eq!(get(environment, "/work", "PWD"), Some("/work"));
        assert_eq!(get(environment, "/work", "PATH"), Some("/bin"));
        let mut pwd = [0_u8; command::MAX_CWD_BYTES + 4];
        let mut entries = [""; command::MAX_ENVIRONMENT];
        let count = child_entries(environment, "/work", &mut pwd, &mut entries)
            .unwrap_or_else(|_| std::process::abort());
        assert!(entries[..count].contains(&"HOME=/custom"));
        assert!(entries[..count].contains(&"LANG=C"));
        assert!(entries[..count].contains(&"PATH=/bin"));
        assert!(entries[..count].contains(&"PWD=/work"));
        assert_eq!(
            entries[..count]
                .iter()
                .filter(|entry| entry.starts_with("HOME="))
                .count(),
            1
        );
    }
}
