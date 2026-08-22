[CmdletBinding()]
param(
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Architecture = 'x86_64',
    [Parameter(Mandatory = $true)]
    [string]$FirmwareCode,
    [Parameter(Mandatory = $true)]
    [string]$FirmwareVars,
    [switch]$SkipVersionCheck
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$qemu = if ($Architecture -eq 'x86_64') { 'qemu-system-x86_64' } else { 'qemu-system-aarch64' }
$command = Get-Command $qemu -ErrorAction Stop
if (-not $SkipVersionCheck) {
    $version = & $command.Source --version | Select-Object -First 1
    if ($version -notmatch 'version 11\.1\.0') {
        throw "expected QEMU 11.1.0, got: $version (use -SkipVersionCheck deliberately)"
    }
}

& (Join-Path $repo 'scripts/build.ps1') -Architecture $Architecture
$image = Join-Path $repo "build/kllm-$Architecture.img"
$firmware = (Resolve-Path -LiteralPath $FirmwareCode).Path
$varsSource = (Resolve-Path -LiteralPath $FirmwareVars).Path
$vars = Join-Path $repo "build/qemu-vars-$Architecture.fd"
Copy-Item -LiteralPath $varsSource -Destination $vars -Force

if ($Architecture -eq 'x86_64') {
    & $command.Source -machine q35 -m 64M -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware" -drive "if=pflash,format=raw,unit=1,file=$vars" -drive "if=virtio,format=raw,file=$image" -no-reboot
} else {
    & $command.Source -machine virt -cpu cortex-a72 -m 128M -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware" -drive "if=pflash,format=raw,unit=1,file=$vars" -drive "if=virtio,format=raw,file=$image" -no-reboot
}
