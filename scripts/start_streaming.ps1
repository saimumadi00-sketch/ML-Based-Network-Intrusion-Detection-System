param(
    [ValidateSet("kafka", "redis")] [string]$Mode = "kafka"
)

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker not found. Install Docker Desktop first."
    exit 1
}

if ($Mode -eq "kafka") {
    docker compose -f "$PSScriptRoot\..\infra\streaming\docker-compose.kafka.yml" up -d
} else {
    docker compose -f "$PSScriptRoot\..\infra\streaming\docker-compose.redis.yml" up -d
}
