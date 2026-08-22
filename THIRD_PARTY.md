# Third-party software

Portable kllm crates have no third-party runtime dependencies.

The firmware application uses `uefi` 0.39 from the rust-osdev project under
MIT OR Apache-2.0. Cargo.lock pins its complete transitive dependency graph.
It is confined to the UEFI machine boundary and is not used after the future
ExitBootServices milestone.

Audit status: API and license reviewed for the Stage 1 firmware-hosted target;
no claim is made that this is a formal security audit.

