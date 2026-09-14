//! Exact six-word native frames; no unspecified input registers.

use crate::Error;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(clippy::unnecessary_wraps)] // Preserve the fallible hosted transport API.
pub(super) fn call(number: u64, words: [u64; 6]) -> Result<[u64; 2], Error> {
    let mut status = number;
    let mut secondary = words[2];
    // SAFETY: The caller encoded all scalar fields and owns any referenced
    // per-thread pages. This gate preserves other registers and returns two result words.
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") status,
            in("rdi") words[0], in("rsi") words[1], inlateout("rdx") secondary,
            in("r10") words[3], in("r8") words[4], in("r9") words[5], options(nostack));
    }
    Ok([status, secondary])
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[allow(clippy::unnecessary_wraps)] // Preserve the fallible hosted transport API.
pub(super) fn call(number: u64, words: [u64; 6]) -> Result<[u64; 2], Error> {
    let mut status = words[0];
    let mut secondary = words[1];
    // SAFETY: The caller encoded the exact scalar frame and owns its IPC pages.
    unsafe {
        core::arch::asm!("svc #0", in("x8") number,
            inlateout("x0") status, inlateout("x1") secondary,
            in("x2") words[2], in("x3") words[3], in("x4") words[4],
            in("x5") words[5], options(nostack));
    }
    Ok([status, secondary])
}

#[cfg(not(target_os = "none"))]
pub(super) fn call(_number: u64, _words: [u64; 6]) -> Result<[u64; 2], Error> {
    Err(Error::UnsupportedTarget)
}

#[allow(clippy::unnecessary_wraps)] // The hosted implementation cannot read TP.
pub(super) fn thread_pointer() -> Result<u64, Error> {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        let pointer;
        // SAFETY: Native entry guarantees the initialized FS:0 self-pointer word.
        unsafe {
            core::arch::asm!("mov {}, fs:[0]", out(reg) pointer, options(nostack, readonly, preserves_flags));
        }
        Ok(pointer)
    }
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let pointer;
        // SAFETY: Reading the current userspace thread pointer changes no state.
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) pointer, options(nostack, nomem, preserves_flags));
        }
        Ok(pointer)
    }
    #[cfg(not(target_os = "none"))]
    Err(Error::UnsupportedTarget)
}
