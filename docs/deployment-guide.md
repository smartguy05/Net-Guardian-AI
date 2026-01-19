# NetGuardian AI - Deployment Guide

This guide covers deploying NetGuardian AI in development and production environments.

## Prerequisites

- Docker 20.10+ or Podman 4.0+
- Docker Compose or Podman Compose
- 4GB+ RAM recommended
- 20GB+ disk space for database and logs

## Quick Start (Development)

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd net-guardian-ai
   ```

2. **Create environment file:**
   ```bash
   cp deploy/.env.example deploy/.env
   ```

3. **Generate secure secrets:**
   ```bash
   # Generate a secure secret key
   openssl rand -hex 32

   # Generate a secure database password
   openssl rand -base64 24
   ```

4. **Edit the `.env` file** with your generated values.

5. **Start the services:**
   ```bash
   cd deploy
   docker-compose up -d
   # or with Podman
   podman-compose up -d
   ```

6. **Check service status:**
   ```bash
   docker-compose ps
   docker-compose logs backend
   ```

7. **Get initial admin password:**
   ```bash
   docker-compose logs backend | grep -A3 "INITIAL ADMIN"
   ```

8. **Access the application:**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

## Environment Configuration

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL database password | `your-secure-password` |
| `SECRET_KEY` | JWT signing secret (min 32 chars) | `openssl rand -hex 32` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode (disable in production) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `CORS_ORIGINS` | `["http://localhost:5173"]` | Allowed CORS origins |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token expiration |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token expiration |

### LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (none) | Anthropic API key for LLM features |
| `LLM_ENABLED` | `true` | Enable/disable LLM features |
| `LLM_MODEL_DEFAULT` | `claude-sonnet-4-20250514` | Default model for analysis |
| `LLM_MODEL_FAST` | `claude-haiku-4-20250514` | Fast model for quick triage |

### Integration Configuration

**AdGuard Home:**
```bash
ADGUARD_ENABLED=true
ADGUARD_URL=http://192.168.1.1:3000
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your-password
ADGUARD_VERIFY_SSL=true
```

**Router Integration (UniFi/pfSense/OPNsense):**
```bash
ROUTER_INTEGRATION_TYPE=unifi  # or: pfsense, opnsense
ROUTER_URL=https://192.168.1.1:8443
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your-password
ROUTER_SITE=default
ROUTER_VERIFY_SSL=true
```

**Ollama Monitoring:**
```bash
OLLAMA_ENABLED=true
OLLAMA_URL=http://localhost:11434
OLLAMA_POLL_INTERVAL_SECONDS=30
OLLAMA_DETECTION_ENABLED=true
```

## Endpoint Agent Deployment

The optional endpoint agent monitors workstations for process and network activity.

### Installation

```bash
# On each endpoint
cd /opt/netguardian
pip install psutil httpx pyyaml

# Copy agent files
cp agent/netguardian_agent.py /opt/netguardian/
cp agent/agent_config.yaml.example /opt/netguardian/agent_config.yaml
```

### Configuration

Edit `agent_config.yaml`:
```yaml
server_url: https://netguardian.local:8000
api_key: your-api-key-here  # Get from Sources > Add Source > API Push
poll_interval: 30
monitor_processes: true
monitor_network: true
verify_ssl: true
```

### Running as a Service (Linux)

```bash
sudo tee /etc/systemd/system/netguardian-agent.service << EOF
[Unit]
Description=NetGuardian Endpoint Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netguardian
ExecStart=/usr/bin/python3 /opt/netguardian/netguardian_agent.py -c /opt/netguardian/agent_config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable netguardian-agent
sudo systemctl start netguardian-agent
```

### Running as a Service (Windows)

Use NSSM (Non-Sucking Service Manager):
```powershell
nssm install NetGuardianAgent "C:\Python312\python.exe" "C:\NetGuardian\netguardian_agent.py -c C:\NetGuardian\agent_config.yaml"
nssm start NetGuardianAgent
```

## NetFlow/sFlow Configuration

NetGuardian can receive NetFlow v5/v9 and sFlow v5 data from network devices.

### Creating a NetFlow Source

```bash
curl -X POST http://localhost:8000/api/v1/sources \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "netflow-router",
    "name": "Router NetFlow",
    "source_type": "udp_listen",
    "parser_type": "netflow",
    "enabled": true,
    "config": {
      "host": "0.0.0.0",
      "port": 2055,
      "queue_size": 10000,
      "allowed_sources": ["192.168.1.1"]
    }
  }'
```

### Creating an sFlow Source

```bash
curl -X POST http://localhost:8000/api/v1/sources \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "sflow-switch",
    "name": "Switch sFlow",
    "source_type": "udp_listen",
    "parser_type": "sflow",
    "enabled": true,
    "config": {
      "host": "0.0.0.0",
      "port": 6343,
      "queue_size": 10000
    }
  }'
```

### Exposing UDP Ports

Add to `docker-compose.yml` collector service:
```yaml
collector:
  ports:
    - "2055:2055/udp"   # NetFlow
    - "6343:6343/udp"   # sFlow
```

### Configuring Network Devices

**Cisco IOS (NetFlow v5):**
```
ip flow-export version 5
ip flow-export destination <netguardian-ip> 2055
interface GigabitEthernet0/0
  ip flow ingress
  ip flow egress
```

**pfSense (softflowd):**
1. Install softflowd package
2. Configure target: `<netguardian-ip>:2055`
3. Select interfaces to monitor

### Performance Tuning

```bash
# Database pool settings
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=1800

# Redis settings
REDIS_MAX_CONNECTIONS=50

# HTTP client settings
HTTP_TIMEOUT_SECONDS=30
HTTP_MAX_CONNECTIONS=100
```

## Production Deployment

### Security Checklist

1. **Generate secure secrets:**
   ```bash
   # Secret key (MUST be unique per deployment)
   openssl rand -hex 32

   # Database password
   openssl rand -base64 24
   ```

2. **Disable debug mode:**
   ```bash
   DEBUG=false
   ```

3. **Configure CORS properly:**
   ```bash
   CORS_ORIGINS=["https://your-domain.com"]
   ```

4. **Use HTTPS** - Place a reverse proxy (nginx, Traefik, Caddy) in front of the application.

5. **Secure database access:**
   - Change default database password
   - Don't expose database port externally
   - Consider network isolation

6. **Review JWT expiration:**
   ```bash
   JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15  # Shorter is more secure
   JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
   ```

### Production docker-compose Override

Create `docker-compose.prod.yml`:

```yaml
version: '3.9'

services:
  backend:
    environment:
      - DEBUG=false
      - LOG_LEVEL=WARNING
    ports:
      - "127.0.0.1:8000:8000"  # Only listen on localhost

  db:
    ports: []  # Don't expose database externally

  redis:
    ports: []  # Don't expose Redis externally

  frontend:
    ports:
      - "127.0.0.1:5173:80"  # Only listen on localhost
```

Start with production overrides:
```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Reverse Proxy Configuration (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name netguardian.yourdomain.com;

    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }
}
```

## Database Management

### Running Migrations

```bash
# Run pending migrations
docker-compose exec backend alembic upgrade head

# Check current migration version
docker-compose exec backend alembic current

# Generate new migration (development only)
docker-compose exec backend alembic revision --autogenerate -m "description"
```

### Database Backup

```bash
# Backup database
docker-compose exec db pg_dump -U netguardian netguardian > backup.sql

# Restore database
cat backup.sql | docker-compose exec -T db psql -U netguardian netguardian
```

### TimescaleDB Maintenance

```bash
# Connect to database
docker-compose exec db psql -U netguardian netguardian

# View hypertable info
SELECT * FROM timescaledb_information.hypertables;

# View chunk info
SELECT * FROM timescaledb_information.chunks;
```

## Log Source Configuration

### Mounting External Logs

Edit `docker-compose.yml` collector service:

```yaml
collector:
  volumes:
    - ./log-sources:/logs:ro
    - /var/log/pfsense:/logs/pfsense:ro
    - /var/log/unifi:/logs/unifi:ro
```

### Creating Log Sources via API

```bash
# Create an API Push source
curl -X POST http://localhost:8000/api/v1/sources \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "home-assistant",
    "name": "Home Assistant",
    "source_type": "api_push",
    "parser_type": "json",
    "enabled": true,
    "config": {}
  }'

# The response includes an API key for pushing events
```

## Monitoring and Troubleshooting

### Checking Service Health

```bash
# All services
docker-compose ps

# Backend health
curl http://localhost:8000/health

# View logs
docker-compose logs -f backend
docker-compose logs -f collector
```

### Common Issues

**1. Database connection errors:**
```bash
# Check database is running
docker-compose exec db pg_isready -U netguardian

# View database logs
docker-compose logs db
```

**2. Redis connection errors:**
```bash
# Check Redis is running
docker-compose exec redis redis-cli ping

# View Redis logs
docker-compose logs redis
```

**3. Migration errors:**
```bash
# Reset migrations (WARNING: destroys data)
docker-compose exec backend alembic downgrade base
docker-compose exec backend alembic upgrade head
```

**4. Permission issues with log mounts:**
```bash
# Check permissions
ls -la ./log-sources

# Fix permissions if needed
chmod -R 755 ./log-sources
```

### Performance Monitoring

```bash
# Database connections
docker-compose exec db psql -U netguardian -c "SELECT count(*) FROM pg_stat_activity;"

# Redis info
docker-compose exec redis redis-cli info stats

# Container resource usage
docker stats
```

## Updating

### Standard Update

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose build
docker-compose up -d

# Run migrations
docker-compose exec backend alembic upgrade head
```

### Zero-Downtime Update

```bash
# Build new images
docker-compose build

# Restart services one by one
docker-compose up -d --no-deps backend
docker-compose up -d --no-deps frontend
docker-compose up -d --no-deps collector
```

## Scaling Considerations

For larger deployments:

1. **External Database:** Use a dedicated PostgreSQL/TimescaleDB server
2. **External Redis:** Use Redis Cluster or managed Redis
3. **Multiple Collectors:** Run multiple collector instances for high-volume log sources
4. **Load Balancer:** Place multiple backend instances behind a load balancer

## Support

- GitHub Issues: https://github.com/your-repo/net-guardian-ai/issues
- Documentation: See `/docs` directory
