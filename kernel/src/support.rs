//! Byte-level helpers shared by every module, and the terminal write path.
//!
//! `fatal` is the only exit that does not return: it writes through the
//! machine port and parks, so the panic handler in the crate root has
//! somewhere to go once the console may already be gone.

use crate::handoff::write_machine_boot_status;
use troe_core::Output;
use troe_task::TaskFault;

pub(crate) const fn usize_as_u64(value: usize) -> u64 {
    value as u64
}

pub(crate) const fn task_fault(fault: troe_machine::IsolatedFault) -> TaskFault {
    match fault {
        troe_machine::IsolatedFault::Translation => TaskFault::Translation,
        troe_machine::IsolatedFault::Permission => TaskFault::Permission,
        troe_machine::IsolatedFault::IllegalInstruction => TaskFault::IllegalInstruction,
        troe_machine::IsolatedFault::InvalidCall => TaskFault::InvalidCall,
        troe_machine::IsolatedFault::ExecutionLeaseExpired => TaskFault::ExecutionLeaseExpired,
    }
}

pub(crate) fn write_all(output: &mut dyn Output, bytes: &[u8]) -> Result<(), ()> {
    troe_core::write_all(output, bytes).map_err(|_| ())
}

pub(crate) fn fatal(message: &[u8]) -> ! {
    let _status = write_machine_boot_status("TROE initialization", false);
    let _written = troe_machine::write(message);
    troe_machine::park()
}

pub(crate) const fn architecture() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
}
