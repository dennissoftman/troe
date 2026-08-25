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
    if !resource.status.success() {
        panic!("clang could not report its resource directory");
    }
    let resource = String::from_utf8(resource.stdout)
        .unwrap_or_else(|error| panic!("clang resource directory was not UTF-8: {error}"));
    let resource_include = PathBuf::from(resource.trim()).join("include");
    let source = manifest.join("c/lua_runtime.c");
    let include = manifest.join("c/include");
    let lua = manifest.join("vendor/lua-5.5.1/src");
    let nanoprintf = manifest.join("vendor/nanoprintf-0.6.1");

    let mut command = Command::new(&compiler);
    command
        .arg(format!("--target={clang_target}"))
        .args([
            "-std=c11",
            "-Oz",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pic",
            "-fno-pie",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fvisibility=hidden",
            "-nostdlibinc",
            "-mcmodel=large",
            "-DTROE_LUA=1",
            "-DLUA_USE_C89=1",
            "-Wall",
            "-Wextra",
            "-Wno-unused-function",
        ])
        .arg("-isystem")
        .arg(resource_include)
        .arg("-I")
        .arg(include)
        .arg("-I")
        .arg(lua)
        .arg("-I")
        .arg(nanoprintf)
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
    if !status.success() {
        panic!("failed to compile the freestanding Lua runtime");
    }

    println!("cargo:rustc-link-arg={}", output.display());
    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("c/include").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("vendor/lua-5.5.1/src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("vendor/nanoprintf-0.6.1").display()
    );
}
