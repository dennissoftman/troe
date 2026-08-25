# ADR 0006: one standard cloud-VM resource policy

Status: accepted, 2026-08-22; original three-profile decision superseded,
2026-08-25.

The original decision defined `micro`, `tiny`, and `full` build profiles. That
taxonomy mixed two separate concerns: bounded resource accounting and support
for materially different machine models. It also made ordinary VM capacity
look like an optional large-machine mode even though cloud virtual machines are
the primary deployment target.

TROE now has exactly one resource policy, `standard`. It targets bounded cloud
VMs and the pinned QEMU acceptance machines. There is no build-time profile
selector, runtime profile switch, embedded profile, or no-MMU composition.
Usable RAM discovered at boot may refine cache and growth budgets within the
standard hard ceilings, but it never selects a different policy or changes
object, command, authority, or ABI semantics.

The standard policy uses practical safety maxima rather than preallocated
arenas. Larger ceilings therefore do not consume their maximum at boot: memory
is charged only when a subsystem actually owns it, and allocation can still
fail below a format ceiling when the current VM lacks enough free pages.
Every externally controlled count and byte length remains checked against an
absolute maximum before allocation or mutation. Accounting, high-water marks,
failure atomicity, and pressure behavior remain mandatory.

KEX parsing applies the standard limits directly. Neither the artifact nor its
startup page carries a redundant profile selector; the former startup-page
profile field is reserved and must be zero. Fixed subsystem policies use named
`standard()` constructors or explicit validated limits rather than
`tiny()`/`full()` presets.

Platform capabilities are independent of resource policy. Virtio transports,
interrupt routes, firmware discovery, and cloud-provider machine differences
belong to named validated platform descriptions under ADR 0016. An unsupported
embedded board is not approximated by shrinking constants or disabling the MMU.

A second resource policy may be introduced only by a later ADR backed by a
measured deployment need that cannot be expressed as ordinary runtime budgets
inside the standard ceilings. Embedded and no-MMU work is out of the current
product scope.

Verification requires one closed standard policy in every build, exact-boundary
tests for its ceilings, no profile-selection CLI, Cargo feature, or wire-field,
and both supported architecture images to boot under the same policy.
Repository policy tests reject reintroduction of the superseded
`micro`/`tiny`/`full` resource branches.
