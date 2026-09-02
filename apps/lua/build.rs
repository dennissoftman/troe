// A build script fails the build by panicking: there is no caller to return an
// error to, and a missing C toolchain or generated tree must stop the build
// with a named reason rather than emit a half-configured artifact.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("lua_runtime.o");
    let target = env::var("TARGET").unwrap_or_default();
    let clang_target = match target.as_str() {
        "x86_64-unknown-none" => "x86_64-unknown-none-elf",
        "aarch64-unknown-none" => "aarch64-unknown-none-elf",
        other => panic!("unsupported Lua KEX target: {other}"),
    };
    let compiler = env::var("CC").unwrap_or_else(|_| "clang".to_owned());
    let resource = Command::new(&compiler)
        .arg("-print-resource-dir")
        .output()
        .unwrap_or_else(|error| panic!("failed to query clang resource directory: {error}"));
    assert!(
        resource.status.success(),
        "clang could not report its resource directory"
    );
    let resource = String::from_utf8(resource.stdout)
        .unwrap_or_else(|error| panic!("clang resource directory was not UTF-8: {error}"));
    let resource_include = PathBuf::from(resource.trim()).join("include");
    let source = manifest.join("c/lua_runtime.c");
    let libc_core = manifest.join("../../sdk/c/troe-kex-runtime/troe_libc_core.c");
    let printf_double = manifest.join("../../sdk/c/troe-kex-runtime/troe_printf_double.h");
    let os_shim = manifest.join("c/troe_os_shim.c");
    let include = manifest.join("../../sdk/c/troe-kex-sysroot/include");
    let lua = manifest.join("vendor/lua-5.5.1/src");
    let nanoprintf = manifest.join("../../sdk/c/troe-kex-runtime/vendor/nanoprintf-0.6.1");

    let mut command = Command::new(&compiler);
    command
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
            "-mcmodel=small",
            "-DTROE_LUA=1",
            "-DLUA_USE_C89=1",
            "-Wall",
            "-Wextra",
            "-Wno-unused-function",
        ])
        .arg("-isystem")
        .arg(resource_include)
        .arg("-I")
        .arg(&include)
        .arg("-I")
        .arg(lua)
        .arg("-I")
        .arg(&nanoprintf)
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&output);
    if target.starts_with("x86_64") {
        command.args([
            "-mno-red-zone",
            "-msse2",
            "-mfpmath=sse",
            "-mno-avx",
            "-mno-avx2",
            "-mno-avx512f",
        ]);
    } else {
        command.args(["-march=armv8-a+simd"]);
    }
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to compile Lua runtime: {error}"));
    assert!(
        status.success(),
        "failed to compile the freestanding Lua runtime"
    );

    println!("cargo:rustc-link-arg={}", output.display());
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", libc_core.display());
    println!("cargo:rerun-if-changed={}", printf_double.display());
    println!("cargo:rerun-if-changed={}", os_shim.display());
    println!("cargo:rerun-if-changed={}", include.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("vendor/lua-5.5.1/src").display()
    );
    println!("cargo:rerun-if-changed={}", nanoprintf.display());
}
