# Storage Layout

- Raw PCAP (cold storage): `data/pcap/` (sync to S3/NFS)
- Processed features: `data/features/` (Parquet/CSV)

## S3 Sync (AWS CLI)

```bash
aws s3 sync data/pcap s3://YOUR_BUCKET/nids/pcap --storage-class GLACIER
aws s3 sync data/features s3://YOUR_BUCKET/nids/features
```

## NFS Mount (Linux)

```bash
sudo mkdir -p /mnt/nids-pcap
sudo mount -t nfs <nfs-server>:/export/nids/pcap /mnt/nids-pcap
```
