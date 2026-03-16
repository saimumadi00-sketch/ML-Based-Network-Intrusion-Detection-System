# Raw PCAP Capture

## Windows (tshark)

1. List interfaces:

```powershell
tshark -D
```

2. Start capture:

```powershell
.\infra\capture\windows_tshark_capture.ps1 -Interface 1 -OutputDir data\pcap -RotateSeconds 300 -BpfFilter "tcp"
```

Npcap is required for capture on Windows.

## Linux (tcpdump)

```bash
bash infra/capture/linux_tcpdump_capture.sh eth0 data/pcap 300 "tcp"
```
