# Zeek Flow Extraction

Use Zeek to extract flow-level logs from PCAP.

## Windows (PowerShell)

```powershell
.\infra\zeek\process_pcap.ps1 -PcapPath data\pcap\capture.pcapng -OutputDir data\zeek
```

If Zeek is installed in WSL (Ubuntu), the script will automatically run it via WSL.

## Linux/macOS

```bash
bash infra/zeek/process_pcap.sh data/pcap/capture.pcapng data/zeek
```

Outputs logs like `conn.log` into `data/zeek/`.
