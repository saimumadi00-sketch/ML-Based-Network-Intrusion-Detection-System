param(
    [string]$Interface = "1",
    [string]$OutputDir = "data\\pcap",
    [int]$RotateSeconds = 300,
    [string]$BpfFilter = ""
)

$tshark = (Get-Command tshark -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
if (-not $tshark) {
    $defaults = @(
        "D:\\I miss her\\Wireshark\\tshark.exe",
        "C:\\Program Files\\Wireshark\\tshark.exe"
    )
    foreach ($path in $defaults) {
        if (Test-Path $path) {
            $tshark = $path
            break
        }
    }
}
if (-not $tshark) {
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
& $tshark -i $Interface -b duration:$RotateSeconds -w (Join-Path $OutputDir "capture.pcapng") @filterArgs
