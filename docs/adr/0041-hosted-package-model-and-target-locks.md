# ADR 0041: hosted package model and target locks

Status: accepted and implemented for the Stage 9 package-contract foundation,
2026-08-27. This decision does not claim native installation, registry trust,
or publication; those require the separately gated lifecycle and trust layers.

## Context

The repository already builds KEX packages, immutable content packs, SCFG
generations, and deterministic boot images. Cargo metadata and those repository
scripts are bootstrap inputs, not a public TROE package API. Treating them as
the package contract would import host paths, feature selection, mutable build
state, and presentation behavior into deployment identity.

Stage 9 instead needs a small package vocabulary that can be validated and
resolved before any native mutation exists. It must bind both supported target
architectures, exact application and toolchain inputs, least authority, and
resource cost while producing identical results independently of catalog
enumeration order.

## Decision

Adopt the PMAN v1 manifest, PLOCK v1 target lock, and TPKG v1 artifact described
in [`package-model-v1.md`](../formats/package-model-v1.md). The reference
implementation is a hosted Python library using only the standard library.
This keeps parsing, typed diagnostics, resolution, artifact construction, and
system-plan modeling reusable without adding a dependency to the native kernel
or portable crates. The CLI imports that library and owns only argument
handling, human/JSON presentation, and explicit absent-path host publication.

Resolution is bounded deterministic backtracking. It selects the highest
version satisfying every reachable range, recomputes constraints when a
version is replaced, and rejects cycles, missing inputs, conflicts, repeated
states, and capacity exhaustion without a partial lock. Locks bind the
canonical manifest, architecture-native KEX artifact, SDK, and toolchain by
SHA-256 and exact artifact length.

The package manifest uses only typed capability names, bounded resource
declarations, service identities, and path-free directory-root declarations.
Activation must resolve directory declarations to the generation-bound objects
from ADR 0040. Neither a package digest nor an absolute path grants trust or
authority.

All machine output uses one stable result and diagnostic schema. Human output
is derived from the same result. Inspection, explanation, diagnostics, and
planning are read-only. Hosted `resolve` and `build` may write only an explicit
output path that does not exist; they do not connect to a running system.

## Consequences

- Both UEFI target triples have one explicit target-lock contract without
  claiming that an architecture implies a deployment environment.
- Dependency and capacity failures are reproducible machine diagnostics rather
  than presentation-only strings.
- TPKG is content-addressable and reproducible but unauthenticated until the
  trust policy verifies its signed release metadata.
- Native generation construction may consume a validated locked plan; it must
  not reinterpret Cargo metadata or invoke the hosted CLI as policy.
- Registry trust/publication and transactional install/update, migration, and
  garbage collection are implemented as the separate boundaries in
  [ADR 0042](0042-package-trust-and-atomic-publication.md) and
  [ADR 0044](0044-transactional-system-lifecycle.md).
