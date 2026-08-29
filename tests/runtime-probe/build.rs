use std::{env, fs, path::PathBuf, process::Command};

fn run(command: &mut Command, purpose: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {purpose}: {error}"));
    assert!(status.success(), "failed to {purpose}");
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repository = manifest.join("../..");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default());
    let sysroot = output.join("troe-c-sysroot");
    if sysroot.exists() {
        fs::remove_dir_all(&sysroot).unwrap_or_else(|error| {
            panic!(
                "failed to clear generated C sysroot {}: {error}",
                sysroot.display()
            )
        });
    }
    let target = env::var("TARGET").unwrap_or_default();
    let (architecture, clang_target) = match target.as_str() {
        "x86_64-unknown-none" => ("x86_64", "x86_64-unknown-none-elf"),
        "aarch64-unknown-none" => ("aarch64", "aarch64-unknown-none-elf"),
        other => panic!("unsupported runtime-probe target: {other}"),
    };
    run(
        Command::new("python3")
            .arg(repository.join("tools/build_c_sysroot.py"))
            .arg(&sysroot)
            .arg("--architecture")
            .arg(architecture),
        "build the shared C sysroot",
    );
    let compiler = env::var("CC").unwrap_or_else(|_| "clang".to_owned());
    let resource = Command::new(&compiler)
        .arg("-print-resource-dir")
        .output()
        .unwrap_or_else(|error| panic!("failed to query clang resource directory: {error}"));
    assert!(resource.status.success(), "clang resource lookup failed");
    let resource = String::from_utf8(resource.stdout)
        .unwrap_or_else(|error| panic!("clang resource path was not UTF-8: {error}"));
    let probe = output.join("runtime_probe.o");
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
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg("-isystem")
        .arg(PathBuf::from(resource.trim()).join("include"))
        .arg("-I")
        .arg(sysroot.join(architecture).join("include"))
        .arg("-c")
        .arg(manifest.join("c/runtime_probe.c"))
        .arg("-o")
        .arg(&probe);
    if architecture == "x86_64" {
        compile.args([
            "-mno-red-zone",
            "-msse2",
            "-mfpmath=sse",
            "-mno-avx",
            "-mno-avx2",
        ]);
    } else {
        compile.arg("-march=armv8-a+simd");
    }
    run(&mut compile, "compile the C runtime probe");
    println!("cargo:rustc-link-arg={}", probe.display());
    println!(
        "cargo:rustc-link-arg={}",
        sysroot.join(architecture).join("lib/libtroe_c.a").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("c/runtime_probe.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repository.join("sdk/c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repository.join("tools/build_c_sysroot.py").display()
    );
}
