# NetFlow / IPFIX Collector

This setup uses `nfcapd` (nfdump) as a NetFlow/IPFIX collector.

## Example (Linux)

```bash
sudo mkdir -p /var/log/nfcapd
sudo nfcapd -l /var/log/nfcapd -p 2055 -D
```

- `-l` output directory
- `-p` listening port (default 2055)
- `-D` daemon mode

Point your router/switch NetFlow/IPFIX export to the collector IP:2055.

## Optional systemd service

See `infra/netflow/nfcapd.service`.
