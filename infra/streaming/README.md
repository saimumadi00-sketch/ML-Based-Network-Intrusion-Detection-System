# Streaming Ingestion

Choose Kafka or Redis for real-time ingestion.

## Kafka (Docker)

```bash
docker compose -f infra/streaming/docker-compose.kafka.yml up -d
```

Create topics (example):

```bash
docker exec -it nids-kafka kafka-topics.sh --create --topic nids-flows --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
```

## Redis (Docker)

```bash
docker compose -f infra/streaming/docker-compose.redis.yml up -d
```

Use Redis Streams (example):

```bash
XADD nids:flows * src_ip 1.2.3.4 dst_ip 5.6.7.8
```
