# 🐳 IoTGuard Docker Deployment Guide

## Quick Start

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access dashboard
open http://localhost:5001
```

---

## Docker Commands Reference

### Building

```bash
# Build the image
docker build -t iotguard:latest .

# Build with no cache (fresh build)
docker build --no-cache -t iotguard:latest .

# Build with specific tag
docker build -t iotguard:v1.0.0 .
```

### Running

```bash
# Run standalone container
docker run -d \
  --name iotguard \
  -p 5001:5001 \
  iotguard:latest

# Run with volume mounts (persist data)
docker run -d \
  --name iotguard \
  -p 5001:5001 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/models:/app/models:ro \
  iotguard:latest

# Run with environment variables
docker run -d \
  --name iotguard \
  -p 5001:5001 \
  -e IOTGUARD_LOG_LEVEL=DEBUG \
  -e IOTGUARD_ALERTING_ENABLED=true \
  -e IOTGUARD_SLACK_WEBHOOK=https://hooks.slack.com/... \
  iotguard:latest
```

### Docker Compose

```bash
# Start all services (detached)
docker-compose up -d

# Start with build
docker-compose up -d --build

# View logs (follow)
docker-compose logs -f

# View specific service logs
docker-compose logs -f iotguard-app

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Restart services
docker-compose restart
```

### Monitoring

```bash
# List running containers
docker ps

# View container logs
docker logs iotguard-app

# Follow logs in real-time
docker logs -f iotguard-app

# View container stats
docker stats iotguard-app

# Execute command in container
docker exec -it iotguard-app bash

# Check health status
docker inspect --format='{{.State.Health.Status}}' iotguard-app
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IOTGUARD_CONFIG` | Configuration file path | `configs/model.yaml` |
| `IOTGUARD_LOG_LEVEL` | Log level (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `IOTGUARD_ENV` | Environment type (iot/it) | `iot` |
| `IOTGUARD_ALERTING_ENABLED` | Enable alerting | `false` |
| `IOTGUARD_SLACK_WEBHOOK` | Slack webhook URL | - |
| `IOTGUARD_TELEGRAM_TOKEN` | Telegram bot token | - |
| `IOTGUARD_TELEGRAM_CHAT_ID` | Telegram chat ID | - |
| `IOTGUARD_USER` | API username | `admin` |
| `IOTGUARD_PASS` | API password | - |
| `IOTGUARD_JWT_SECRET` | JWT signing secret | auto-generated |

---

## Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./data` | `/app/data` | Features, alerts, runtime data |
| `./logs` | `/app/logs` | Application logs |
| `./models` | `/app/models` | Trained ML models (read-only) |
| `./configs` | `/app/configs` | Configuration files (read-only) |

---

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 5001 | Dashboard | Flask API + Web UI |

---

## Health Checks

The container includes a health check that verifies the API is responding:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health/live')"
```

Check health status:
```bash
docker inspect --format='{{json .State.Health}}' iotguard-app | jq
```

---

## Production Deployment

### Using Gunicorn (recommended for production)

Modify the `CMD` in Dockerfile:
```dockerfile
CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "2", "scripts.api_dashboard:app"]
```

Or override at runtime:
```bash
docker run -d \
  --name iotguard \
  -p 5001:5001 \
  iotguard:latest \
  gunicorn -b 0.0.0.0:5001 -w 2 scripts.api_dashboard:app
```

### Using Nginx Reverse Proxy

```yaml
# docker-compose.yml
services:
  iotguard-app:
    # ... existing config ...

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./deploy/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - iotguard-app
```

### Resource Limits

```yaml
services:
  iotguard-app:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker logs iotguard-app

# Check if port is in use
netstat -an | grep 5001

# Run interactively to debug
docker run -it --rm iotguard:latest bash
```

### Health check failing

```bash
# Test health endpoint manually
docker exec iotguard-app curl http://localhost:5001/health/live

# Check Python dependencies
docker exec iotguard-app pip list
```

### Permission issues

```bash
# Fix volume permissions on Linux
chmod -R 777 ./data ./logs
```

### Cannot access dashboard

```bash
# Verify container is running
docker ps

# Check port mapping
docker port iotguard-app

# Test from inside container
docker exec iotguard-app curl http://localhost:5001
```

---

## Example docker-compose.yml

```yaml
version: "3.9"

services:
  iotguard-app:
    build: .
    container_name: iotguard-app
    environment:
      - IOTGUARD_CONFIG=configs/model.yaml
      - IOTGUARD_LOG_LEVEL=INFO
      - IOTGUARD_ALERTING_ENABLED=true
      - IOTGUARD_SLACK_WEBHOOK=${SLACK_WEBHOOK}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./models:/app/models:ro
      - ./configs:/app/configs:ro
    ports:
      - "5001:5001"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5001/health/live')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    restart: unless-stopped
    networks:
      - iotguard-net

networks:
  iotguard-net:
    driver: bridge
```

---

**Happy Deploying! 🚀**
