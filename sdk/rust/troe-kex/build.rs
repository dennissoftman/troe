//! Compile the optional, compiler-managed native thread-local bootstrap.

use std::{env, error::Error, io, path::PathBuf, process::Command};

fn run(command: &mut Command) -> Result<(), Box<dyn Error>> {
    // Match the qualified C profile's exclusion of ambient driver inputs.
    for variable in [
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "COMPILER_PATH",
        "LIBRARY_PATH",
        "GCC_EXEC_PREFIX",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "CCC_OVERRIDE_OPTIONS",
        "CLANG_CONFIG_FILE_USER_DIR",
        "CLANG_CONFIG_FILE_SYSTEM_DIR",
        "LDEMULATION",
        "LD_RUN_PATH",
    ] {
        command.env_remove(variable);
    }
    command.env("SOURCE_DATE_EPOCH", "946684800");
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other("native SDK TLS helper build failed").into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/threading/local.c");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    if env::var_os("CARGO_FEATURE_NATIVE_THREADS").is_none()
        || env::var("CARGO_CFG_TARGET_OS")? != "none"
    {
        return Ok(());
    }
    let architecture = env::var("CARGO_CFG_TARGET_ARCH")?;
    let (target, flags): (&str, &[&str]) = match architecture.as_str() {
        "x86_64" => (
            "x86_64-unknown-none-elf",
            &[
                "-mno-red-zone",
                "-march=x86-64",
                "-msse2",
                "-mfpmath=sse",
                "-mno-avx",
                "-mno-avx2",
            ],
        ),
        "aarch64" => (
            "aarch64-unknown-none-elf",
            &["-march=armv8-a+simd", "-mno-outline-atomics"],
        ),
        _ => return Err(io::Error::other("unsupported native SDK architecture").into()),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR"))?);
    let source = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| io::Error::other("CARGO_MANIFEST_DIR"))?,
    )
    .join("src/threading/local.c");
    let object = output.join("thread_local.o");
    let compiler = env::var_os("CC").unwrap_or_else(|| "clang".into());
    run(Command::new(compiler)
        .arg("--no-default-config")
        .arg(format!("--target={target}"))
        .args([
            "-std=c11",
            "-O2",
            "-ffreestanding",
            "-fno-builtin",
            "-fPIC",
            "-ftls-model=local-exec",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            // This bootstrap function only returns a TLS address. It must run
            // before a runtime can initialize its stack-protector guard.
            "-fno-stack-protector",
            "-fno-ident",
            "-nostdinc",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .args(flags)
        .arg("-c")
        .arg(source)
        .arg("-o")
        .arg(&object))?;
    let archive = env::var_os("AR").unwrap_or_else(|| "llvm-ar".into());
    run(Command::new(archive)
        .arg("crs")
        .arg(output.join("libtroe_thread_local.a"))
        .arg(object))?;
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=troe_thread_local");
    Ok(())
}
