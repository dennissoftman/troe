# TROE Tooling & Package Management Specification

**Status:** Draft post-MVP architecture; no implementation is implied

**Scope:** Developer tooling, package management, builds, deployment, extensibility, maintenance, and ecosystem design.

**Out of scope:** Kernel architecture, scheduler, IPC implementation, VM internals, and other kernel mechanisms covered by [CORE-SPEC.md](CORE-SPEC.md).

**Naming convention:** The product is TROE and the CLI executable is `troe`.
Command examples use `troe` literally. The reserved manifest filenames are
`troe.toml`, `troe.lock`, and `troe-system.toml`; their schemas remain draft
until separately accepted. Other angle-bracketed names describe domain values
or types, not placeholders for the TROE name.

This document extends the core specification; it does not replace it. The core
specification and accepted ADRs define the current execution, authority,
resource-profile, and security models. If an example here requires a facility
that the core roadmap has not reached, the example is future-facing and MUST
NOT be read as current behavior.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** carry
the meaning defined by the core specification. Command output, package names,
versions, paths, and manifest fragments are illustrative until their schemas or
interfaces are separately versioned and accepted.

---

## 1. Vision

The tooling should feel less like a collection of Unix utilities and more like **one coherent interface to the operating system**.

The guiding principle is:

> **Make the correct, secure, reproducible and efficient path the easiest path.**

A developer should be able to go from source code to a running isolated service with almost no knowledge of the underlying system:

```bash
troe new web-api --python
cd web-api
troe run
```

Likewise, writing a driver should feel surprisingly close to writing an ordinary application:

```bash
troe new driver e1000
troe dev
```

Installing software should be declarative and transactional:

```bash
troe add redis
troe apply
```

And understanding the machine should not require memorizing dozens of unrelated utilities:

```bash
troe status
troe inspect web-api
troe explain web-api
troe logs web-api
troe doctor
```

The CLI, SDK, package manager, build system and documentation are therefore **one product**, not independent projects.

---

## 2. Core Principles

### 2.1 Extensibility without baseline cost

The project must not equate minimalism with limited functionality.

A system may eventually contain:

- Python
- Go
- Rust
- databases
- desktop environments
- NVIDIA/CUDA
- Vulkan
- USB
- Bluetooth
- complex networking
- third-party drivers

But functionality that isn't installed or active should impose approximately no runtime cost.

**Minimal is the default configuration, not an architectural limitation.**

---

### 2.2 Composition over installation

Traditional package managers modify a machine.

The tooling should instead **construct a desired system state**.

Conceptually:

```text
system specification
        ↓
dependency resolution
        ↓
capability resolution
        ↓
artifact resolution
        ↓
system generation
        ↓
atomic activation
```

A package installation should therefore never become an uncontrolled sequence of scripts modifying `/etc`, creating users, starting daemons and leaving files behind.

---

### 2.3 Packages declare needs, not assumptions

Packages must explicitly describe:

1. what they depend on;
2. what resources they require;
3. what capabilities they require;
4. what services they provide;
5. what interfaces they expose;
6. what lifecycle actions they support.

For example:

```toml
[package]
name = "example-api"
version = "1.4.2"

[runtime]
python = ">=3.14,<3.15"

[capabilities]
network.listen = ["tcp:8000"]
network.connect = ["postgres:5432"]
filesystem.read = ["app"]
filesystem.write = ["data"]
clock = true
random = true

[resources]
memory.recommended = "64MiB"
memory.maximum = "128MiB"

[provides]
service = "example-api"
```

Security information is therefore not maintained separately from package metadata.

---

## 3. The Command-Line Interface

Once the package-capable tooling layer exists, it should expose **one canonical
control-plane command**:

```bash
troe
```

Subcommands provide the rest of the interface.

```text
troe
├── new
├── run
├── build
├── test
├── dev
├── add
├── remove
├── update
├── apply
├── rollback
├── package
├── publish
├── search
├── inspect
├── explain
├── status
├── logs
├── trace
├── profile
├── docs
├── doctor
└── system
```

The underlying libraries must remain independently usable through the SDK. The CLI is a client of those APIs rather than containing unique system logic.

This prevents the CLI from becoming an irreplaceable monolith.

The planned TROE CLI is distinct from the current statically linked recovery shell.
The shell continues to dispatch small statically linked commands such as
`cat`, `mem`, and `halt` directly; those commands are part of the tiny recovery
environment and are not rewritten as `troe cat`, `troe mem`, or similar
subcommands.

During the early roadmap, repository scripts and Cargo remain the bootstrap
developer interface. They MUST remain deterministic and auditable, and they
MUST NOT pretend that package transactions or application isolation exist
before the corresponding system mechanisms land. A hosted implementation of
the planned TROE CLI MAY arrive first, but it must call the same libraries and consume
the same versioned formats intended for the native client.

---

## 4. Projects

A native project contains a manifest:

```text
my-service/
├── troe.toml
├── src/
├── tests/
└── README.md
```

Creation:

```bash
troe new my-service --rust
```

or:

```bash
troe new my-service --python
troe new my-service --go
troe new my-service --c
```

Templates are extensible packages themselves.

Eventually:

```bash
troe new my-service --template fastapi
troe new my-service --template grpc-rust
troe new driver --template pci
```

Third parties can publish templates without changing the CLI.

---

## 5. Manifest Design

`troe.toml` should be the canonical description of package/application intent.

Example:

```toml
schema = 1

[package]
name = "weather-api"
version = "1.2.0"
license = "MIT"

[runtime]
python = "3.14"

[entrypoint]
command = ["python", "-m", "weather"]

[dependencies]
fastapi = "^0.120"
uvicorn = "^0.40"

[capabilities.network]
listen = ["tcp:8000"]
connect = ["api.weather.example:443"]

[capabilities.filesystem]
read = ["assets"]
write = ["data"]

[resources]
memory.recommended = "64MiB"
memory.maximum = "128MiB"
cpu.recommended = 0.25
```

The format must remain deliberately boring.

No executable configuration language should be required for ordinary packages.

Complexity belongs in tooling, not manifests.

The tooling model uses separate documents for separate kinds of state:

| Document | Meaning | May contain resolved artifact identities? |
|---|---|---:|
| `troe.toml` | project and package intent | no |
| `troe.lock` | exact, target-specific dependency resolution | yes |
| `troe-system.toml` | desired packages, services, policy, and persistent-volume declarations | no |
| generation record | immutable result of resolving and composing a system | yes |

All four formats MUST be versioned before they are consumed by a released
system image. A lock file and generation record MUST identify the target
architecture, project SDK/ABI, selected Standard resource policy and explicit
ceilings, resolver version, and every artifact by content identity. Secrets and
machine-local credentials MUST be referenced, never embedded in these files.

---

## 6. Package Model

A native package is **not an archive of files to scatter around the filesystem**.

It is an immutable artifact containing:

```text
Package
├── identity
├── version
├── binaries/assets
├── dependencies
├── interfaces
├── capabilities
├── resource metadata
├── documentation
├── provenance
└── cryptographic identity
```

Packages enter a content-addressed store.

Conceptually (the path is not a promised VFS ABI):

```text
/store/
    91fa...-python-3.14/
    8ac1...-openssl-4.0/
    d382...-weather-api-1.2/
```

Installed generations reference immutable objects.

Objects are shared whenever possible.

Package identity and content identity are different. A human-facing name and
version select candidates; a cryptographic digest identifies the exact
canonical artifact. Signatures bind that digest plus the artifact's target,
manifest, provenance, and compatibility metadata. Mutable application data is
never part of the package object.

---

## 7. No Arbitrary Install Scripts

One of the most important rules:

> Packages should not execute arbitrary privileged code during installation.

Avoid:

```text
postinstall.sh
preinstall.sh
configure-machine.sh
```

These destroy reproducibility and make security analysis difficult.

Instead packages request structured operations:

```toml
[state]
directories = ["data"]

[services]
register = ["weather-api"]

[interfaces]
requires = ["network.tcp"]
```

The system performs those operations itself.

If an escape hatch eventually becomes necessary, it must be explicit, sandboxed and treated as exceptional.

This restriction applies to activation and installation. Source builds MAY run
package-supplied build logic only inside a declared, bounded build sandbox with
no ambient host authority, a locked input graph, explicit network policy, and
captured outputs. Build logic never gains authority over the running system.

---

## 8. Dependency Resolution

Dependencies should support both traditional packages and abstract interfaces.

For example:

```toml
[dependencies]
python = "^3.14"

[requires]
tls = ">=1"
database.postgres.client = ">=3"
```

The resolver could satisfy `tls` through an appropriate provider.

This allows implementations to evolve without packages depending unnecessarily on particular components.

---

## 9. System Generations

Every successful system change creates a generation.

```bash
troe apply
```

might produce:

```text
Generation 42

+ python 3.14.2
+ weather-api 1.2.0
~ openssl 4.0.1 → 4.0.2

Estimated persistent storage:
+38.4 MiB

Expected baseline memory:
+2.1 MiB

Capabilities introduced:
+ outbound HTTPS for weather-api

Activate generation 42? [Y/n]
```

Activation should be atomic.

Previous generations remain available:

```bash
troe system generations
```

and:

```bash
troe rollback
```

should be boringly reliable.

A failed update must not leave a half-configured machine.

Atomic activation means atomically selecting an already constructed and
validated generation; it does not make arbitrary data migration transactional.
The model separates:

- immutable package objects;
- an immutable generation containing resolved objects, service definitions,
  capability grants, and non-secret configuration;
- explicitly named persistent volumes and secret references whose lifetimes
  are independent of a generation; and
- one small, crash-consistent active-generation pointer.

Rollback switches executable and declarative configuration state. It MUST NOT
silently rewind, delete, or reinterpret persistent data. A package that needs a
data migration must declare compatible schema ranges, forward and rollback
behavior, required free space, and whether rollback becomes unsafe. The plan
must stop for explicit approval when safe rollback cannot be preserved.

Activation SHOULD use a two-phase flow: construct and verify the candidate,
then switch the active pointer and run bounded health checks. On boot or health
failure, the system must retain a path to the previous generation and the
statically linked recovery shell. Garbage collection treats bootable and
operator-pinned generations as roots.

---

## 10. Resource Cost as Package Metadata

Efficiency is a first-class project property.

Packages may provide measured resource information:

```toml
[resources.measured]
idle_memory = "2.8MiB"
startup_peak = "7.1MiB"
disk = "4.2MiB"
```

These values must be explicitly identified as measured estimates rather than guarantees.

The tooling can supplement them with local observations.

For example:

```bash
troe explain redis
```

could show:

```text
redis 8.x

Installed size:
    7.2 MiB

Current private memory:
    4.8 MiB

Shared memory:
    2.1 MiB

System services required:
    network.tcp
    filesystem

Additional kernel resources:
    96 KiB

Capabilities:
    listen tcp:6379
    read/write redis-data
```

This makes resource usage visible instead of mysterious.

---

## 11. Explainability

`explain` should become one of the project's signature features.

```bash
troe explain my-api
```

Example:

```text
my-api

WHY IS IT RUNNING?

Required by:
    system.services.api

Runtime:
    python@3.14

Dependencies:
    python
    openssl
    network.tcp

MEMORY

Private             31.4 MiB
Shared               8.7 MiB
Kernel resources   212 KiB

CAPABILITIES

✓ TCP listen :8000
✓ DNS
✓ connect db:5432
✓ read /app
✓ write /data

Not granted:
✗ raw devices
✗ other process memory
✗ unrestricted filesystem
✗ administrative interfaces
```

The system should be able to explain **why almost anything exists**.

```bash
troe explain package openssl
troe explain capability network.raw
troe explain service network.tcp
troe explain memory my-api
```

---

## 12. Development Environments

The tooling should make reproducible development environments trivial.

```bash
git clone ...
cd project
troe dev
```

The project manifest defines the environment.

No manually maintained machine state should be required.

Example:

```toml
[dev]
rust = "workspace"
llvm = "compatible"
python = "3.14"

[dev.tools]
lldb = true
```

`troe dev` creates an isolated environment using the same package infrastructure as production.

Therefore:

> Development and production use the same resolver and artifact model.

This eliminates an entire class of “works on my machine” problems.

Before the system supports isolated applications, `troe dev` MAY compose a
hosted environment. The command must state where execution occurs and which
guarantees are unavailable; a host process is not to be presented as
system-enforced isolation.

---

## 13. SDK Design

The SDK must have layers.

```text
Project SDK

├── Core API
│   ├── processes
│   ├── memory
│   ├── capabilities
│   ├── IPC
│   └── synchronization
│
├── System API
│   ├── filesystem
│   ├── networking
│   ├── devices
│   └── services
│
├── Runtime API
│   ├── Rust
│   ├── C
│   ├── Go
│   └── language ports
│
└── Driver SDK
    ├── PCI
    ├── MMIO
    ├── DMA
    ├── interrupts
    └── device protocols
```

The SDK itself must be versioned independently from implementation details.

Applications target **stable interfaces**, not kernel internals.

The first native SDK begins only with the loadable-application work in Stage 7
of the core roadmap. Its capability vocabulary MUST map to actual handles or
service interfaces; manifest declarations alone are not a security boundary.
Likewise, driver SDK declarations do not confer hardware isolation before the
underlying task, address-space, and device-authority mechanisms exist.

---

## 14. Driver Development

Driver development should receive the same attention as application development.

```bash
troe new driver e1000 --pci
```

generates:

```text
e1000/
├── troe.toml
├── src/
│   └── main.rs
├── tests/
└── docs/
```

The manifest could contain:

```toml
[driver]
type = "pci"

[device.pci]
vendor = "8086"
devices = ["100e", "100f"]

[capabilities]
pci.device = true
dma = true
interrupts = true
```

Development:

```bash
troe dev
```

Testing:

```bash
troe test --qemu
```

Tracing:

```bash
troe trace driver:e1000
```

Inspection:

```bash
troe inspect driver:e1000
```

A driver should receive only the hardware resources it needs.

The tooling should make the safe approach easier than bypassing it.

---

## 15. Hardware Test Harness

The tooling should eventually provide first-class virtual hardware testing.

Example:

```toml
[test.hardware]
platform = "qemu"
device = "e1000"
memory = "64MiB"
```

Then:

```bash
troe test
```

can:

1. build the driver;
2. construct a temporary system image;
3. start QEMU;
4. attach the emulated hardware;
5. execute integration tests;
6. collect logs;
7. collect crashes;
8. report leaked resources.

Eventually:

```bash
troe test --hardware pci:01:00.0
```

could safely run selected tests against real hardware.

---

## 16. Observability from Day One

Debugging must not be added years later.

The project should define structured tracing immediately.

```bash
troe trace my-api
```

could expose:

```text
process.spawn
service.connect
fs.open
net.connect
memory.map
ipc.call
```

Filtering:

```bash
troe trace my-api --ipc
troe trace my-api --network
troe trace driver:nvidia --device
```

Performance:

```bash
troe profile my-api
```

might report:

```text
CPU                     7.2%
IPC calls              12,814/s
IPC CPU                  0.4%
Context switches         4,821/s
Page faults                124/s
Allocations             18.1 MiB/s
Network                 81.2 MB/s
```

Efficiency becomes measurable instead of ideological.

---

## 17. Documentation Is an SDK Feature

Documentation is considered part of API completeness.

A stable public API is not considered complete until it has:

- semantic description;
- capability requirements;
- failure conditions;
- resource behavior;
- concurrency guarantees;
- examples;
- compatibility guarantees.

For example:

```bash
troe docs fs.open
```

could display:

```text
fs.open(path, rights) -> Result<File>

Opens a filesystem object.

CAPABILITIES

filesystem.read
or
filesystem.write

depending on requested rights.

IPC

1 request
1 response

ALLOCATIONS

Kernel:
    1 capability-table entry

Filesystem service:
    implementation dependent

THREAD SAFETY

Safe across threads.

ERRORS

NOT_FOUND
ACCESS_DENIED
INVALID_PATH
RESOURCE_LIMIT

EXAMPLES

Rust
C
Go
```

Documentation should also be available offline.

---

## 18. Documentation Must Be Machine-Readable

Public APIs should carry structured metadata from which documentation can be generated.

That enables:

```bash
troe docs
```

but also:

```bash
troe sdk describe fs.open --json
```

IDE integration can consume the same information.

This prevents documentation and reality from drifting apart.

---

## 19. IDE Integration

The SDK should eventually expose a language-server-like protocol for system concepts.

An IDE could understand:

```rust
service::connect::<Network>()
```

and show:

```text
Requires capability:
network.connect
```

If the manifest doesn't grant it:

```text
⚠ Application does not declare network.connect.

Add capability to troe.toml?
```

The IDE could therefore understand not just syntax and types, but **OS authority**.

That would make capabilities feel native rather than burdensome.

---

## 20. Capability-Aware Builds

Build tooling should be able to compare software behavior with its declaration.

Suppose:

```toml
[capabilities]
network = false
```

but integration testing observes an attempted network connection.

The tooling should report:

```text
Capability violation

weather-parser attempted:
    network.connect

Declared:
    no network access

Origin:
    src/update.rs:142
```

During development, capability failures should be extraordinarily easy to diagnose.

---

## 21. Package Registry

The registry should contain more than binaries.

```text
Registry entry

├── artifact
├── source identity
├── dependencies
├── capabilities
├── bounded resource requests
├── supported architectures
├── SDK compatibility
├── signatures
├── SBOM
├── documentation
└── provenance
```

Search becomes richer:

```bash
troe search http-server
```

and potentially:

```bash
troe search http-server --memory '<10MiB'
```

or:

```bash
troe search database --arch aarch64
```

---

## 22. Reproducible Builds

Packages should strive toward deterministic artifacts.

Given:

```text
source
+
dependency graph
+
toolchain
+
build configuration
```

The build should ideally produce the same content identity.

The build environment itself comes from the package store.

No implicit `/usr/bin/gcc`.

No reliance on whatever version happens to exist on the build machine.

---

## 23. Package Provenance

Every package should be able to answer:

```bash
troe inspect python --provenance
```

with something conceptually like:

```text
python 3.14.2

Source:
    upstream CPython 3.14.2

Project patches:
    7

Built using:
    LLVM 22.0.1
    Project SDK 0.8

Build:
    reproducible

Signature:
    troe-core-registry

Source available:
    yes
```

The ecosystem should make supply-chain inspection normal rather than specialist work.

---

## 24. Lock Files

Applications receive a lock file:

```text
troe.lock
```

It records exact artifact identities rather than merely versions.

Therefore:

```bash
troe build --locked
```

six months later should resolve the same environment.

The manifest expresses **intent**.

The lock file expresses **resolution**.

Resolution is target-specific. A lock entry MUST include the architecture,
platform compatibility, SDK/ABI compatibility, source identity, feature
selection, bounded resource requests, and artifact digest. If one lock file
contains resolutions for multiple targets, those graphs must be separate and
unambiguous. `--locked` MUST fail rather than consult an unrecorded source or
silently rewrite the lock file.

---

## 25. Updates

Updates should be previewable.

```bash
troe update --plan
```

Example:

```text
UPDATE PLAN

python
3.14.1 → 3.14.2

openssl
4.0.0 → 4.0.1

Affected services:
    api
    worker

New capabilities:
    none

Removed capabilities:
    none

Estimated disk delta:
    +4.8 MiB

Expected downtime:
    none
```

Then:

```bash
troe apply
```

---

## 26. Security Changes Must Be Visible

A package update requesting additional authority is not an ordinary update.

For example:

```text
⚠ CAPABILITY CHANGE

image-tool 2.1 previously had:

    filesystem.read

image-tool 2.2 requests:

  + network.connect

Reason declared by package:
    remote model downloads
```

The tooling should make changes in authority painfully obvious.

---

## 27. Service Interfaces

Services should expose versioned protocols.

For example:

```text
filesystem@2
network.tcp@1
gpu.compute@1
display@3
```

Consumers depend on interfaces rather than implementations whenever possible.

This is essential for long-term maintainability.

A new network implementation should not require recompiling every application if it implements the existing protocol.

---

## 28. Protocol Evolution

Interfaces require explicit compatibility rules.

Example:

```text
network.tcp@1.4

compatible:
    1.0–1.4

breaking:
    2.x
```

Old protocol implementations can coexist temporarily if necessary.

The tooling should expose why:

```bash
troe explain interface network.tcp@1
```

```text
network.tcp@1 remains active because:

    legacy-api requires <=1.x

network.tcp@2 consumers:
    web-api
    ssh
```

This prevents mysterious compatibility baggage from accumulating.

---

## 29. Garbage Collection

Because packages and generations are immutable, cleanup becomes explicit:

```bash
troe gc
```

Preview:

```bash
troe gc --plan
```

```text
Unused artifacts:
    84

Recoverable:
    1.7 GiB

Protected by rollback generations:
    412 MiB
```

Nothing currently referenced may disappear.

---

## 30. Application Bundles

The tooling should support self-contained application descriptions without duplicating dependencies unnecessarily.

For distribution:

```bash
troe package
```

produces a package descriptor/artifact.

Deployment:

```bash
troe deploy server.example
```

The receiving machine resolves content it already possesses and transfers only missing artifacts.

---

## 31. Remote Deployment

Remote machines should use the same model as local machines.

Conceptually:

```bash
troe deploy prod
```

should perform:

```text
local desired state
        ↓
resolve
        ↓
build/fetch artifacts
        ↓
transfer missing content
        ↓
construct remote generation
        ↓
health check
        ↓
atomic activation
```

No SSH shell script should be necessary.

---

## 32. Extending the CLI

The CLI itself must not become a bottleneck.

Extensions can provide namespaced commands:

```bash
troe gpu ...
troe cloud ...
troe python ...
```

But extensions should interact through stable APIs.

They should not receive unrestricted authority merely because they're CLI extensions.

Example:

```toml
[extension]
name = "example-vendor"

[commands]
provides = ["gpu"]

[capabilities]
system.devices.read = true
```

The plugin model itself follows the project's capability philosophy.

---

## 33. Package Manager Extensions

Package types must not be hard-coded forever.

A provider architecture can support:

```text
native packages
Python packages
Rust crates
Go modules
firmware
drivers
debug symbols
SDKs
```

However, external ecosystems should ideally be **adapted into the project's package graph**, not allowed to independently mutate the system.

For example:

```text
PyPI
 ↓
Python resolver adapter
 ↓
project dependency graph
 ↓
immutable environment
```

Thus:

```bash
troe add python:fastapi
```

could eventually integrate PyPI without turning the machine into an unmanaged `pip` environment.

---

## 34. Python Experience

Python should be a flagship compatibility target.

For example:

```bash
troe new api --python
cd api
troe add python:fastapi
troe add python:uvicorn
troe run
```

The developer shouldn't need to manually create a virtual environment.

The project already **is** an isolated environment.

For compatibility:

```bash
pip install ...
```

may eventually exist.

But native project workflows should prefer:

```bash
troe add python:...
```

because that keeps dependency state reproducible.

---

## 35. Rust Experience

Rust can receive especially deep integration.

```bash
troe new daemon --rust
```

Tooling automatically selects the project target.

```bash
troe build
```

handles:

```text
cargo
↓
project target
↓
artifact metadata
↓
capability manifest
↓
native package
```

Developers can still use Cargo directly.

The project should enhance existing ecosystems rather than unnecessarily replace their excellent tooling.

---

## 36. Diagnostics

There should be one command for answering:

> Why isn't this working?

```bash
troe doctor
```

Examples:

```text
✓ package store
✓ system generation
✓ network service
✓ DNS
✓ filesystem
✓ clock
✓ registry access

⚠ python-api

  Cannot start because capability
  filesystem.write:data references
  an unavailable volume.

Suggested fix:

    troe volume create data
```

For a specific application:

```bash
troe doctor python-api
```

For hardware:

```bash
troe doctor gpu0
```

This should be treated as a core feature, not a collection of ad-hoc diagnostics.

---

## 37. Error Design

Errors must be actionable.

Bad:

```text
ERROR 0x17
```

Still bad:

```text
Permission denied.
```

Preferred:

```text
weather-api cannot connect to api.example.com:443.

The process has:
    network.connect = ["db:5432"]

It requires:
    network.connect = ["api.example.com:443"]

To grant it:

    troe capability add weather-api \
        network.connect api.example.com:443

Documentation:
    troe docs network.connect
```

Developer experience should extend all the way into runtime failures.

---

## 38. Stable Machine-Readable Output

Every important command should support structured output:

```bash
troe status --json
troe inspect --json
troe explain --json
troe profile --json
```

The human-readable CLI must never become the API.

Automation uses stable schemas.

Humans use beautiful output.

---

## 39. API-First Architecture

Internally:

```text
CLI
IDE
GUI
CI
remote deployment
package registry
third-party tools
        │
        ▼
    Project APIs
        │
        ▼
system services
```

The CLI should have no secret privileges or hidden implementation paths.

Anything the official tooling can do should eventually be possible through documented APIs with appropriate authority.

This is critical for extensibility.

---

## 40. Maintenance Philosophy

The project should aggressively prevent accidental permanent interfaces.

A feature progresses through:

```text
experimental
    ↓
preview
    ↓
stable
    ↓
deprecated
    ↓
removed
```

Experimental APIs explicitly carry no compatibility promise.

Stable APIs receive defined compatibility guarantees.

This gives early development freedom without destroying long-term trust.

---

## 41. Compatibility Database

The project should record what software has actually been tested.

For example:

```bash
troe compat python
```

```text
CPython

3.14    ✓ supported
3.13    ✓ supported
3.12    community
3.11    unsupported

Tests:
    stdlib       99.8%
    asyncio      ✓
    multiprocessing ✓
    ssl          ✓
    sqlite3      ✓
```

Eventually:

```bash
troe compat pytorch
troe compat postgres
troe compat redis
```

This is much better than vague statements such as “probably POSIX compatible.”

---

## 42. Testing Packages

Package publication should support automated compatibility tests.

```bash
troe package test
```

could verify:

```text
✓ manifest schema
✓ dependencies resolvable
✓ capability declarations
✓ architecture metadata
✓ documentation
✓ reproducible build
✓ unit tests
✓ integration tests
✓ resource leaks
✓ package isolation
```

Core packages should face stricter requirements.

---

## 43. First-Class Leak Detection

A capability/microkernel architecture gives the project an opportunity to make resource leaks unusually visible.

When a test exits:

```text
RESOURCE CHECK

✓ threads released
✓ memory objects released
✓ IPC endpoints released
✗ 2 file handles remain

Created at:
    src/cache.rs:81
```

Driver development could similarly detect unreleased DMA mappings, interrupts and device handles.

This should be built early enough that the project's own services benefit from it.

---

## 44. Package Trust

Repositories should support different trust levels.

For example:

```text
core
verified
community
local
```

But trust should be cryptographic and policy-driven rather than merely branding.

A production system could declare:

```toml
[policy.packages]
allow = ["core", "verified"]
```

A development workstation could permit community packages.

---

## 45. System Policies

Administrators should be able to impose constraints above individual package requests.

Example:

```toml
[policy.network]
deny_raw = true

[policy.packages]
require_signed = true

[policy.resources]
service_memory_max = "1GiB"
```

A package requesting something forbidden should fail during planning, before activation.

---

## 46. System Presets

The tooling can provide convenient predefined system presets without changing the underlying model.

```bash
troe system init --preset cloud-minimal
```

or:

```bash
troe system init --preset developer
```

or eventually:

```bash
troe system init --preset workstation
troe system init --preset cuda
```

System presets are simply versioned configuration expanded into ordinary
`troe-system.toml` intent. They do not select resource profiles: every build
uses the single standard bounded policy accepted by ADR 0006. A preset such as
`cloud-minimal` may select packages, services, and explicit runtime budgets
within those hard ceilings. Tooling MUST show the expanded result in `--plan`
output.

No special editions of the project should be necessary.

---

## 47. The Magic Principle

The system should appear magical because **the abstractions line up**, not because tooling hides unpredictable behavior.

For example:

```bash
troe add postgres
```

may automatically determine:

```text
package
    ↓
runtime dependencies
    ↓
storage requirement
    ↓
network service
    ↓
capabilities
    ↓
service registration
```

But:

```bash
troe add postgres --plan
```

must reveal every decision.

Therefore:

> **Simple by default. Explicit on demand.**

This should apply throughout the project.

---

## 48. Escape Hatches

The project must remain hackable.

Advanced users need access to lower-level mechanisms.

The philosophy should not be:

> You aren't allowed to do that.

It should be:

> Here's the safe high-level abstraction. If it doesn't fit your problem, here's the documented lower-level interface.

For example:

```text
high-level driver SDK
        ↓
device API
        ↓
PCI/DMA primitives
```

The abstraction hierarchy remains open downward.

This is essential if the project is expected to support unforeseen hardware and workloads decades later.

---

## 49. Avoiding Ecosystem Lock-In

The project should not require every ecosystem to abandon its existing tools.

Good:

```text
Cargo ─────┐
Go modules ├── project integration layer
PyPI ──────┘
```

Bad:

```text
Rewrite every package ecosystem because
The project has its own package manager.
```

The project owns **system composition and execution state**.

Language package managers can continue owning language-level dependency ecosystems where appropriate.

Adapters connect the two.

---

## 50. Suggested Repository Structure

Tooling should extend the current workspace rather than begin as a disconnected
product repository. Logical boundaries may eventually look like:

```text
troe/
├── crates/                  current portable system crates
├── host/                    current hosted composition root
├── kernel/                  current firmware/native composition root
├── tools/                   bootstrap image and verification tools
├── scripts/                 bootstrap entry points
├── schemas/                 future versioned tooling formats
└── tooling/                 future hosted/native composition roots
    └── crates/
        ├── manifest/
        ├── resolver/
        ├── store/
        ├── system-model/
        ├── diagnostics/
        ├── protocol/
        └── cli/
```

This is a dependency direction, not a request to create empty crates or
directories now. A new crate needs a concrete ownership, test, dependency, or
unsafe-code boundary, matching the core specification's crate policy. The
exact repository boundaries can evolve, but
**resolver/store/manifest logic should never become CLI logic**.

Libraries first.

CLI second.

---

## 51. First Package-Capable Release Requirements

Before the system can install and activate packages, tooling must establish several foundations.

### Required before native package activation

- versioned manifest schema;
- immutable/content-addressed package artifacts;
- deterministic dependency graph;
- lock files;
- capability declarations;
- package/service separation;
- machine-readable diagnostics;
- a crash-consistent active-generation pointer;
- rollback and persistent-data boundary;
- SDK versioning;
- structured tracing;
- documentation metadata;
- clear experimental/stable API lifecycle.

### Can come later

- public registry;
- remote deployment;
- IDE plugins;
- resource prediction;
- PyPI integration;
- advanced provenance;
- distributed builds;
- binary caches;
- graphical package browser;
- CUDA tooling.

The architecture should permit these from the beginning without requiring their implementation immediately.

These are requirements for the package subsystem, not for release 0.1. The
current Cargo lock, deterministic KEFS/FAT builders, size gates, and repository
scripts are bootstrap mechanisms. They demonstrate useful constraints but are
not native packages, system generations, or the public tooling API.

### 51.1 Alignment with the core roadmap

Tooling is gated by the mechanisms it claims to manage:

| Core stage | Tooling that may become real |
|---|---|
| Stages 0–3 | bootstrap scripts, deterministic image builds, size/accounting reports, hosted schema experiments |
| Stages 4–6 | structured task/service inspection and tracing over versioned, bounded interfaces |
| Stage 7 | native SDK, package artifact validation, `build`, `run`, and package-local `inspect`/`explain` |
| Stage 8 | persistent content store, desired-system manifest, generation construction, service activation, and local rollback |
| Stage 9 | supported updates, recovery policy, registry trust, publication, remote deployment, and compatibility commitments |

A hosted prototype MAY precede its native stage, but acceptance tests and user
output must distinguish simulated or host-provided behavior from guarantees
enforced by the system.

---

## 52. First Tooling Milestone

The first tooling milestone is a hosted package-model demonstration that does
not mutate a running system and can land alongside work toward Stage 7
without claiming installation:

```bash
git clone hello-service
cd hello-service

troe package check
troe build --locked
```

Then:

```bash
troe inspect hello-service
troe explain hello-service
troe package
```

Its exit criteria are:

- versioned manifest and lock schemas;
- deterministic resolution for both primary architectures;
- canonical artifact construction and round-trip validation;
- capability/resource metadata that uses core vocabulary;
- stable machine-readable inspection output; and
- no mutation of a running system.

After Stages 7 and 8 provide real application loading and persistent system
composition, the native extension of this milestone is:

```bash
troe run
troe add ./hello-service.pkg
troe apply --plan
troe apply
```

It must install into a clean VM, run with declared authority, remove cleanly,
and roll back to the prior bootable generation:

```bash
troe remove hello-service
troe apply
troe rollback
```

At no point should unexplained mutable state remain behind.

---

## 53. Second Tooling Milestone: Python

The first major compatibility demonstration:

```bash
troe new api --python
troe add python:fastapi
troe add python:uvicorn
troe run
```

Then:

```bash
troe explain api
```

should provide a complete picture of:

- why Python exists;
- which packages are mapped;
- private versus shared memory;
- network authority;
- filesystem authority;
- CPU usage;
- dependency relationships.

The benchmark can then compare the identical application on this system and conventional Linux distributions.

---

## 54. Third Tooling Milestone: Driver SDK

A small virtual device driver demonstrates that the tooling is not only pleasant for applications.

```bash
troe new driver example --pci

troe test --qemu
```

The entire build → boot → hardware emulation → integration-test → diagnostics cycle should require essentially no manual VM configuration.

If this experience is good early, complex future ports such as networking, storage and eventually GPUs become much more maintainable.

---

## 55. Long-Term Experience

Eventually a developer should be able to type:

```bash
troe add nvidia-driver
troe add cuda
troe add python:pytorch
troe apply
```

and have the tooling resolve:

```text
NVIDIA driver
    │
    ├── required device interfaces
    ├── firmware
    ├── GPU services
    └── userspace libraries

CUDA
    │
    └── GPU compute interface

PyTorch
    │
    ├── Python
    └── CUDA
```

Then:

```bash
python
```

```python
>>> import torch
>>> torch.cuda.is_available()
True
```

The implementation underneath that may be extraordinarily complicated.

**The user's experience should not be.**

That is the purpose of the tooling architecture.

---

## 56. Definition of Success

The tooling succeeds when these statements are simultaneously true:

**For newcomers**

> “I installed and ran my application without learning the entire operating system.”

**For experienced developers**

> “Nothing was hidden from me when I wanted to inspect it.”

**For system administrators**

> “I know exactly what changed, why it exists, what it can access and how to undo it.”

**For driver authors**

> “The OS gave me safe primitives, testing infrastructure and useful diagnostics instead of forcing me to build everything myself.”

**For maintainers**

> “Adding a feature did not require modifying the package manager, CLI, kernel and build system simultaneously.”

**For performance-conscious users**

> “I can see what I'm paying for.”

---

## 57. Core Tooling Philosophy

The entire design can be reduced to six rules:

1. **Nothing exists without a reason.**
2. **Nothing receives authority implicitly.**
3. **Nothing mutates the system invisibly.**
4. **Everything important can explain itself.**
5. **Every abstraction has a documented lower layer.**
6. **Functionality costs resources only when functionality is used.**

The goal is not merely to create a good package manager.

The goal is to make the operating system, SDK, package manager, debugger, build
system, and deployment platform feel as though they were designed by the
**same team on the same day**.

Because, unlike almost every mature operating system, they actually can be.
