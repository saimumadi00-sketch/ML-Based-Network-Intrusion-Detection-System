param(
    [string]$Interface = "1",
    [string]$OutputDir = "data\\pcap",
    [int]$RotateSeconds = 300,
    [string]$BpfFilter = ""
)

if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    Write-Error "tshark not found. Install Wireshark (includes tshark) and ensure it is on PATH."
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Starting capture on interface $Interface"
Write-Host "Output dir: $OutputDir"
Write-Host "Rotate: ${RotateSeconds}s"
if ($BpfFilter) { Write-Host "BPF filter: $BpfFilter" }

$filterArgs = @()
if ($BpfFilter) { $filterArgs = @("-f", $BpfFilter) }

# Ring buffer rotation by duration
& tshark -i $Interface -b duration:$RotateSeconds -w (Join-Path $OutputDir "capture.pcapng") @filterArgs
