param(
    [string]$Interface = "",
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

if (-not $Interface) {
    Write-Host "Select an interface index from:"
    & $tshark -D
    Write-Host "Re-run with -Interface <index>."
    exit 1
}

& "$PSScriptRoot\..\infra\capture\windows_tshark_capture.ps1" -Interface $Interface -OutputDir $OutputDir -RotateSeconds $RotateSeconds -BpfFilter $BpfFilter
