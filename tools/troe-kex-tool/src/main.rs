//! Canonical hosted builder and inspector for TROE KEX applications.
#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = troe_kex_tool::run(std::env::args_os().skip(1)) {
        eprintln!("kex: {error}");
        std::process::exit(2);
    }
}
