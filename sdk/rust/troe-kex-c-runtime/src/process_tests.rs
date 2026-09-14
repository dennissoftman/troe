#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate std;

use core::ffi::CStr;
use std::{boxed::Box, string::String, vec};

use super::*;

#[test]
fn retained_strings_survive_source_retirement_and_remain_c_writable() {
    let mut storage = Box::new(Strings::new());
    let configuration = {
        let mut arguments = [0; command::MAX_INVOCATION_BYTES];
        let mut environment = [0; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let count =
            command::encode("/work", &["python", "-c", "print(1)"], &mut arguments).unwrap();
        let invocation = command::Invocation::parse(&arguments[..count]).unwrap();
        let count = command::encode_environment(&["HOME=/private", "TEST=value"], &mut environment)
            .unwrap();
        let environment = command::Environment::parse(&environment[..count]).unwrap();
        storage.initialize(invocation, environment).unwrap()
    };
    assert_eq!(configuration.argc, 3);
    // SAFETY: The boxed strings stay at the address used during initialization.
    // Input buffers are already gone; all pointer targets must be copied storage.
    unsafe {
        assert_eq!(CStr::from_ptr(*configuration.argv).to_bytes(), b"python");
        assert_eq!(CStr::from_ptr(configuration.cwd).to_bytes(), b"/work");
        assert!((*configuration.argv.add(3)).is_null());
        let mut values = vec![];
        for index in 0..=command::MAX_ENVIRONMENT {
            let value = *configuration.environment.add(index);
            if value.is_null() {
                break;
            }
            values.push(CStr::from_ptr(value).to_str().unwrap());
        }
        assert!(values.contains(&"PWD=/work"));
        assert!(values.contains(&"HOME=/private"));
        assert!(values.contains(&"TEST=value"));
        **configuration.argv = c_char::try_from(b'P').unwrap();
        assert_eq!(CStr::from_ptr(*configuration.argv).to_bytes(), b"Python");
    }
}

#[test]
fn exact_argument_and_cwd_limits_keep_the_pointer_terminators() {
    let mut storage = Box::new(Strings::new());
    let argument = String::from_utf8(vec![b'a'; command::MAX_ARGUMENT_BYTES]).unwrap();
    let cwd = String::from_utf8(vec![b'/'; command::MAX_CWD_BYTES]).unwrap();
    let mut arguments = [0; command::MAX_INVOCATION_BYTES];
    let count = command::encode(&cwd, &[&argument], &mut arguments).unwrap();
    let mut environment = [0; command::MAX_ENCODED_ENVIRONMENT_BYTES];
    let env_count = command::encode_environment(&[], &mut environment).unwrap();
    let configuration = storage
        .initialize(
            command::Invocation::parse(&arguments[..count]).unwrap(),
            command::Environment::parse(&environment[..env_count]).unwrap(),
        )
        .unwrap();
    // SAFETY: These pointers name the complete initialized, boxed arrays.
    unsafe {
        assert_eq!(
            CStr::from_ptr(*configuration.argv).to_bytes().len(),
            argument.len()
        );
        assert!((*configuration.argv.add(1)).is_null());
        assert_eq!(
            CStr::from_ptr(configuration.cwd).to_bytes().len(),
            cwd.len()
        );
    }
}

#[test]
fn invalid_c_strings_never_publish_partial_offsets() {
    let mut storage = [0xa5; 4];
    let mut offset = 0;
    assert!(copy_string("a\0b", &mut storage, &mut offset).is_err());
    assert!(copy_string("long", &mut storage, &mut offset).is_err());
    assert_eq!(offset, 0);
    assert_eq!(storage, [0xa5; 4]);
    assert!(copy_string("abc", &mut storage, &mut offset).is_ok());
    assert_eq!(offset, 4);
    assert_eq!(storage, *b"abc\0");
    assert!(copy_string("", &mut storage, &mut offset).is_err());
}
