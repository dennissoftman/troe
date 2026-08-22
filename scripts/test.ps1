[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'rustfmt failed' }
    cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'clippy failed' }
    cargo clippy -p kllm-kernel --target x86_64-unknown-uefi -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'x86-64 UEFI clippy failed' }
    cargo clippy -p kllm-kernel --target aarch64-unknown-uefi -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'AArch64 UEFI clippy failed' }
    cargo test --workspace
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
    python tools/mkefs.py rootfs assets/root.kefs --check
    if ($LASTEXITCODE -ne 0) { throw 'embedded filesystem is stale' }
    python tools/check_unsafe.py . --expected 0
    if ($LASTEXITCODE -ne 0) { throw 'unsafe inventory changed' }
    cargo run --quiet -p kllm-host -- --script tests/smoke.ksh
    if ($LASTEXITCODE -ne 0) { throw 'host smoke test failed' }
    & scripts/build.ps1
} finally {
    Pop-Location
}
