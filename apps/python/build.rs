// A build script fails the build by panicking: there is no caller to return an
// error to, and a missing C toolchain or generated tree must stop the build
// with a named reason rather than emit a half-configured artifact.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{env, path::PathBuf, process::Command};

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(
        env::var_os(name).unwrap_or_else(|| panic!("{name} must name a generated CPython path")),
    )
}

fn required_text(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set by tools/build_cpython.py"))
}

fn run(command: &mut Command, purpose: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {purpose}: {error}"));
    assert!(status.success(), "failed to {purpose}");
}

fn main() {
    let manifest = env::var_os("TROE_CPYTHON_APP_ROOT").map_or_else(
        || PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default()),
        PathBuf::from,
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default());
    let build = required_path("TROE_CPYTHON_BUILD");
    let source = required_path("TROE_CPYTHON_SOURCE");
    let sysroot = required_path("TROE_CPYTHON_SYSROOT");
    let version = required_text("TROE_CPYTHON_VERSION");
    let series = required_text("TROE_CPYTHON_SERIES");
    let expected_architecture = required_text("TROE_CPYTHON_ARCHITECTURE");
    let target = env::var("TARGET").unwrap_or_default();
    let (architecture, clang_target) = match target.as_str() {
        "x86_64-unknown-none" => ("x86_64", "x86_64-unknown-none-elf"),
        "aarch64-unknown-none" => ("aarch64", "aarch64-unknown-none-elf"),
        other => panic!("unsupported CPython KEX target: {other}"),
    };
    assert_eq!(architecture, expected_architecture);

    let compiler = env::var("CC").unwrap_or_else(|_| "clang".to_owned());
    let resource = Command::new(&compiler)
        .arg("-print-resource-dir")
        .output()
        .unwrap_or_else(|error| panic!("failed to query clang resource directory: {error}"));
    assert!(resource.status.success(), "clang resource lookup failed");
    let resource = String::from_utf8(resource.stdout)
        .unwrap_or_else(|error| panic!("clang resource path was not UTF-8: {error}"));

    let mut objects = Vec::new();
    for source_name in ["troe_cpython.c", "troe_cpython_compat.c"] {
        let object = output.join(format!("{}.o", source_name.trim_end_matches(".c")));
        let mut compile = Command::new(&compiler);
        compile
            .arg(format!("--target={clang_target}"))
            .args([
                "-std=c11",
                "-O2",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fPIC",
                "-ffunction-sections",
                "-fdata-sections",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-fvisibility=hidden",
                "-nostdlibinc",
                "-D__TROE__=1",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(format!("-DTROE_CPYTHON_ARCHITECTURE=\"{architecture}\""))
            .arg(format!("-DTROE_CPYTHON_VERSION=\"{version}\""))
            .arg(format!("-DTROE_CPYTHON_SERIES=\"{series}\""))
            .arg("-isystem")
            .arg(PathBuf::from(resource.trim()).join("include"))
            .arg("-I")
            .arg(manifest.join("include"))
            .arg("-I")
            .arg(&build)
            .arg("-I")
            .arg(source.join("Include"))
            .arg("-I")
            .arg(source.join("Include/internal"))
            .arg("-I")
            .arg(sysroot.join(architecture).join("include"))
            .arg("-c")
            .arg(manifest.join("c").join(source_name))
            .arg("-o")
            .arg(&object);
        if architecture == "x86_64" {
            compile.args([
                "-mno-red-zone",
                "-msse2",
                "-mfpmath=sse",
                "-mno-avx",
                "-mno-avx2",
                "-mno-avx512f",
            ]);
        } else {
            compile.arg("-march=armv8-a+simd");
        }
        run(&mut compile, source_name);
        objects.push(object);
    }

    for object in objects {
        println!("cargo:rustc-link-arg={}", object.display());
    }
    println!(
        "cargo:rustc-link-arg={}",
        build.join(format!("libpython{series}.a")).display()
    );
    for library in [
        "libHacl_Hash_MD5.a",
        "libHacl_Hash_SHA1.a",
        "libHacl_Hash_SHA2.a",
        "libHacl_Hash_SHA3.a",
        "libHacl_Hash_BLAKE2.a",
        "libHacl_HMAC.a",
    ] {
        let archive = build.join("Modules/_hacl").join(library);
        if archive.is_file() {
            println!("cargo:rustc-link-arg={}", archive.display());
            println!("cargo:rerun-if-changed={}", archive.display());
        }
    }
    // Bundled dependencies of the reviewed static modules.
    for library in [
        "Modules/_decimal/libmpdec/libmpdec.a",
        "Modules/expat/libexpat.a",
    ] {
        let archive = build.join(library);
        if archive.is_file() {
            println!("cargo:rustc-link-arg={}", archive.display());
            println!("cargo:rerun-if-changed={}", archive.display());
        }
    }
    println!(
        "cargo:rustc-link-arg={}",
        sysroot.join(architecture).join("lib/libtroe_c.a").display()
    );

    for variable in [
        "TROE_CPYTHON_BUILD",
        "TROE_CPYTHON_SOURCE",
        "TROE_CPYTHON_SYSROOT",
        "TROE_CPYTHON_VERSION",
        "TROE_CPYTHON_SERIES",
        "TROE_CPYTHON_ARCHITECTURE",
        "TROE_CPYTHON_APP_ROOT",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    println!("cargo:rerun-if-changed={}", manifest.join("c").display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("include").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        build.join(format!("libpython{series}.a")).display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        sysroot.join(architecture).join("lib/libtroe_c.a").display()
    );
}
