param(
    [string]$Interface = "",
    [string]$OutputDir = "data\\pcap",
    [int]$RotateSeconds = 300,
    [string]$BpfFilter = ""
)

if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    Write-Error "tshark not found. Install Wireshark (includes tshark) and ensure it is on PATH."
    exit 1
}

if (-not $Interface) {
    Write-Host "Select an interface index from:"
    tshark -D
    Write-Host "Re-run with -Interface <index>."
    exit 1
}

& "$PSScriptRoot\..\infra\capture\windows_tshark_capture.ps1" -Interface $Interface -OutputDir $OutputDir -RotateSeconds $RotateSeconds -BpfFilter $BpfFilter
