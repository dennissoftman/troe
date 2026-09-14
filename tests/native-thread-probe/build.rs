//! Compile the consumer's independent compiler-TLS canaries.

use std::{env, error::Error, io, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let output = PathBuf::from(env::var("OUT_DIR")?).join("canary.o");
    let target = match env::var("CARGO_CFG_TARGET_ARCH")?.as_str() {
        "x86_64" => "x86_64-unknown-none-elf",
        "aarch64" => "aarch64-unknown-none-elf",
        _ => return Err(io::Error::other("unsupported native consumer target").into()),
    };
    let status = Command::new(env::var_os("CC").unwrap_or_else(|| "clang".into()))
        .arg("--no-default-config")
        .arg(format!("--target={target}"))
        .args([
            "-std=c11",
            "-O2",
            "-ffreestanding",
            "-fno-builtin",
            "-fPIC",
            "-ftls-model=local-exec",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-ident",
            "-nostdinc",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg("-c")
        .arg(root.join("canary.c"))
        .arg("-o")
        .arg(&output)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("native canary build failed").into());
    }
    println!("cargo:rustc-link-arg={}", output.display());
    println!("cargo:rerun-if-changed=canary.c");
    println!("cargo:rerun-if-env-changed=CC");
    Ok(())
}
