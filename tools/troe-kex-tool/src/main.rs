//! Canonical hosted builder and inspector for TROE KEX applications.
#![forbid(unsafe_code)]

fn main() {
    if troe_kex_tool::is_rustc_wrapper() {
        match troe_kex_tool::run_rustc_wrapper(std::env::args_os().skip(1)) {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(error) => {
                eprintln!("kex rustc wrapper: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Err(error) = troe_kex_tool::run(std::env::args_os().skip(1)) {
        eprintln!("kex: {error}");
        std::process::exit(2);
    }
}
