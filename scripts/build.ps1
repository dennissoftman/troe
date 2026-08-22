[CmdletBinding()]
param(
    [ValidateSet('all', 'x86_64', 'aarch64')]
    [string]$Architecture = 'all'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    python tools/mkefs.py rootfs assets/root.kefs
    if ($LASTEXITCODE -ne 0) { throw 'KEFS generation failed' }

    $targets = if ($Architecture -eq 'all') { @('x86_64', 'aarch64') } else { @($Architecture) }
    foreach ($arch in $targets) {
        $target = if ($arch -eq 'x86_64') { 'x86_64-unknown-uefi' } else { 'aarch64-unknown-uefi' }
        cargo build --locked -p kllm-kernel --release --target $target
        if ($LASTEXITCODE -ne 0) { throw "Rust build failed for $arch" }
        $efi = Join-Path $repo "target/$target/release/kllm-kernel.efi"
        $image = Join-Path $repo "build/kllm-$arch.img"
        python tools/mkfat.py --arch $arch --efi $efi --output $image
        if ($LASTEXITCODE -ne 0) { throw "image build failed for $arch" }
        python tools/size_report.py --arch $arch --efi $efi --rootfs assets/root.kefs --image $image
        if ($LASTEXITCODE -ne 0) { throw "size report failed for $arch" }
        if ((Get-Item -LiteralPath $image).Length -gt 16MB) { throw "image exceeds the 16 MiB ceiling: $image" }
    }
} finally {
    Pop-Location
}
