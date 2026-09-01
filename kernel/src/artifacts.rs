//! Native application images embedded for the acceptance runs.
//!
//! Selects the architecture-correct KEX package out of `tests/kex-corpus/` for
//! each probe the acceptance image performs. The paths are relative to this
//! file, so the module must stay directly under `kernel/src/`.

use crate::probes::ApplicationProbe;
#[cfg(feature = "acceptance-probes")]
use crate::service::diagnostics::DIAGNOSTICS_FAULT_PROBE_REQUESTED;
#[cfg(feature = "acceptance-probes")]
use core::sync::atomic::Ordering;
use troe_application::Target;

pub(crate) const fn native_application_target() -> Target {
    #[cfg(target_arch = "x86_64")]
    {
        Target::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        Target::Aarch64
    }
}

pub(crate) fn native_diagnostics_server_artifact() -> (&'static [u8], bool) {
    #[cfg(feature = "acceptance-probes")]
    if DIAGNOSTICS_FAULT_PROBE_REQUESTED.swap(false, Ordering::AcqRel) {
        #[cfg(target_arch = "x86_64")]
        {
            return (
                include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-fault-server.kex"),
                true,
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            return (
                include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-fault-server.kex"),
                true,
            );
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        (
            include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-server.kex"),
            false,
        )
    }
    #[cfg(target_arch = "aarch64")]
    {
        (
            include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-server.kex"),
            false,
        )
    }
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn native_diagnostics_benchmark_artifact() -> &'static [u8] {
    #[cfg(target_arch = "x86_64")]
    {
        include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-benchmark-server.kex")
    }
    #[cfg(target_arch = "aarch64")]
    {
        include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-benchmark-server.kex")
    }
}

pub(crate) fn native_kex_artifact(probe: ApplicationProbe) -> &'static [u8] {
    match probe {
        ApplicationProbe::Calls => {
            #[cfg(target_arch = "x86_64")]
            {
                include_bytes!("../../tests/kex-corpus/native-calls-x86_64.kex")
            }
            #[cfg(target_arch = "aarch64")]
            {
                include_bytes!("../../tests/kex-corpus/native-calls-aarch64.kex")
            }
        }
        #[cfg(feature = "acceptance-probes")]
        ApplicationProbe::Spin => {
            #[cfg(target_arch = "x86_64")]
            {
                include_bytes!("../../tests/kex-corpus/native-spin-x86_64.kex")
            }
            #[cfg(target_arch = "aarch64")]
            {
                include_bytes!("../../tests/kex-corpus/native-spin-aarch64.kex")
            }
        }
        #[cfg(feature = "acceptance-probes")]
        ApplicationProbe::HeapGrowthLimit => {
            #[cfg(target_arch = "x86_64")]
            {
                include_bytes!("../../tests/kex-corpus/native-heap-growth-limit-x86_64.kex")
            }
            #[cfg(target_arch = "aarch64")]
            {
                include_bytes!("../../tests/kex-corpus/native-heap-growth-limit-aarch64.kex")
            }
        }
        #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
        ApplicationProbe::ThreadPointer => {
            include_bytes!("../../tests/kex-corpus/native-thread-pointer-aarch64.kex")
        }
        #[cfg(feature = "acceptance-probes")]
        ApplicationProbe::InvalidCall => {
            #[cfg(target_arch = "x86_64")]
            {
                include_bytes!("../../tests/kex-corpus/native-invalid-call-x86_64.kex")
            }
            #[cfg(target_arch = "aarch64")]
            {
                include_bytes!("../../tests/kex-corpus/native-invalid-call-aarch64.kex")
            }
        }
        #[cfg(feature = "acceptance-probes")]
        ApplicationProbe::UnexpectedReturn => {
            #[cfg(target_arch = "x86_64")]
            {
                include_bytes!("../../tests/kex-corpus/native-unexpected-return-x86_64.kex")
            }
            #[cfg(target_arch = "aarch64")]
            {
                include_bytes!("../../tests/kex-corpus/native-unexpected-return-aarch64.kex")
            }
        }
    }
}
