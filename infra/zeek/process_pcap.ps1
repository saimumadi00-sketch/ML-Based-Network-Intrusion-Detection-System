param(
    [string]$PcapPath,
    [string]$OutputDir = "data\\zeek"
)

if (-not $PcapPath) {
    Write-Error "PcapPath is required"
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if (Get-Command zeek -ErrorAction SilentlyContinue) {
    & zeek -r $PcapPath local
    Move-Item -Force *.log $OutputDir
    exit 0
}

if (Get-Command wsl -ErrorAction SilentlyContinue) {
    $wslPcap = & wsl wslpath -a $PcapPath
    $wslOut = & wsl wslpath -a $OutputDir
    & wsl -d Ubuntu -- bash -lc "mkdir -p $wslOut && cd $wslOut && /opt/zeek/bin/zeek -r $wslPcap local"
    exit 0
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    $pcapDir = Split-Path -Parent (Resolve-Path $PcapPath)
    $pcapFile = Split-Path -Leaf $PcapPath
    $outDir = Resolve-Path $OutputDir
    & docker run --rm -v "$pcapDir:/pcap" -v "$outDir:/out" zeek/zeek -r "/pcap/$pcapFile" local
    Get-ChildItem -Path $pcapDir -Filter *.log | Move-Item -Destination $OutputDir -Force
    exit 0
}

Write-Error "Zeek not found. Install Zeek or Docker, then re-run."
exit 1
