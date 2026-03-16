param(
    [string]$PcapPath,
    [string]$OutputDir = "data\\zeek"
)

& "$PSScriptRoot\..\infra\zeek\process_pcap.ps1" -PcapPath $PcapPath -OutputDir $OutputDir
