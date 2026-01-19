# NetGuardian AI

AI-powered home network security monitoring system with multi-source log collection, device inventory, anomaly detection, LLM-assisted threat analysis, and automated response capabilities.

## Current Status: Phase 5 (Polish & Extensions) - COMPLETE

All phases complete! The system provides comprehensive network security monitoring with:
- Multi-source log collection (API, file, push, UDP flow data)
- Device inventory with auto-discovery
- Anomaly detection with behavioral baselines
- LLM-powered threat analysis (Claude integration)
- Active response (device quarantine via AdGuard/router)
- Ollama LLM monitoring for prompt injection/jailbreak detection
- Optional endpoint agent for workstation monitoring
- NetFlow/sFlow support for network flow analysis

## Features

### Implemented
- **Multi-Source Log Collection** - API polling, file watching, HTTP push ingestion
- **Device Inventory** - Auto-discovery from network events
- **Real-time Event Processing** - Redis Streams event bus
- **Authentication & RBAC** - JWT tokens, admin/operator/viewer roles
- **Dashboard** - Device list, event feed, alerts, source management
- **TimescaleDB** - Time-series optimized storage for events
- **Anomaly Detection** - Behavioral baselines with statistical detection
- **LLM Integration** - Claude-powered alert analysis and natural language queries
- **Active Response** - AdGuard Home and router-level device quarantine
- **Response Playbooks** - Automated action chains with configurable triggers
- **Audit Logging** - Full security event audit trail
- **Ollama LLM Monitoring** - Detect prompt injection, jailbreaks, and LLM-malware

### Phase 5 Complete
- **Ollama LLM Monitoring** - Detect prompt injection, jailbreaks, data exfiltration
- **Performance Optimization** - Database/HTTP connection pooling, Redis caching layer
- **Security Hardening** - Login rate limiting, password validation, startup checks
- **Documentation** - Deployment guide, user guide, updated API docs
- **Endpoint Agent** - Optional lightweight agent for workstation monitoring
- **NetFlow/sFlow Support** - Network flow data collection and analysis

## Quick Start

### Prerequisites
- Docker or Podman with Compose
- 2GB RAM minimum

### Start the Stack

```bash
cd deploy
cp .env.example .env  # Edit with your settings
podman-compose up -d  # or docker-compose
```

### Run Database Migrations

```bash
podman exec netguardian-backend alembic upgrade head
```

### Access

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |

### Default Login

On first startup, an admin user is created with a randomly generated password. Check the backend logs:

```bash
podman logs netguardian-backend | grep "Initial admin"
```

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Frontend      |     |    Backend       |     |    Collector     |
|  React + Vite    |<--->|    FastAPI       |<--->|    Worker        |
|  Port 5173       |     |    Port 8000     |     |                  |
+------------------+     +------------------+     +------------------+
                                  |                       |
                                  v                       v
                         +------------------+     +------------------+
                         |   TimescaleDB    |     |     Redis        |
                         |   Port 5432      |     |   Port 6379      |
                         +------------------+     +------------------+
```

## Project Structure

```
net-guardian-ai/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # REST endpoints
│   │   ├── collectors/      # Log collectors (API, file, UDP)
│   │   ├── parsers/         # Log format parsers
│   │   ├── models/          # SQLAlchemy models
│   │   ├── events/          # Redis event bus
│   │   ├── services/        # Business logic services
│   │   └── core/            # Security, caching, rate limiting
│   ├── alembic/             # Database migrations
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── pages/           # Page components
│   │   └── api/             # API client
│   └── Dockerfile
├── agent/                   # Optional endpoint agent
│   ├── netguardian_agent.py # Standalone monitoring agent
│   ├── agent_config.yaml.example
│   └── requirements.txt
├── deploy/
│   ├── docker-compose.yml
│   └── .env
└── docs/
    ├── prd.md               # Product requirements
    ├── implementation-status.md
    ├── deployment-guide.md  # Deployment documentation
    └── user-guide.md        # End-user documentation
```

## Configuration

Key environment variables in `deploy/.env`:

```bash
# Database
DB_PASSWORD=your-secure-password
DB_POOL_SIZE=20              # Connection pool size (default: 20)

# Authentication (generate with: openssl rand -hex 32)
SECRET_KEY=your-64-char-hex-key
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# LLM Integration
ANTHROPIC_API_KEY=sk-ant-your-api-key
LLM_ENABLED=true

# AdGuard Home Integration
ADGUARD_ENABLED=true
ADGUARD_URL=http://192.168.1.1:3000
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your-password

# Router Integration - optional (unifi, pfsense, opnsense)
ROUTER_INTEGRATION_TYPE=unifi
ROUTER_URL=https://192.168.1.1:8443
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your-password

# Ollama LLM Monitoring - optional
OLLAMA_ENABLED=true
OLLAMA_URL=http://localhost:11434
OLLAMA_DETECTION_ENABLED=true
```

See [Deployment Guide](docs/deployment-guide.md) for full configuration reference.

## Adding Log Sources

### Via UI
1. Login as admin
2. Navigate to Sources page
3. Click "Add Source"
4. Configure source type, parser, and connection details

### Via API
```bash
curl -X POST http://localhost:8000/api/v1/sources \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my-adguard",
    "name": "AdGuard Home",
    "source_type": "api_pull",
    "parser_type": "adguard",
    "config": {
      "url": "http://192.168.1.1:3000",
      "auth_type": "basic",
      "username": "admin",
      "password": "password",
      "poll_interval_seconds": 30
    }
  }'
```

## Development

### Backend
```bash
cd backend
pip install -e .
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
# Backend unit tests
cd backend
pip install -e ".[dev]"
pytest tests/ -v

# Run specific test categories
pytest tests/parsers/ -v    # Parser tests only
pytest tests/collectors/ -v  # Collector tests only

# With coverage
pytest tests/ --cov=app --cov-report=html
```

```bash
# Frontend type checking
cd frontend
npm run build  # Runs TypeScript check then builds
```

## Roadmap

- **Phase 1** (Complete): Foundation - Multi-source collection, device inventory, dashboard
- **Phase 2** (Complete): Anomaly Detection - Behavioral baselines, statistical detection
- **Phase 3** (Complete): LLM Integration - Claude-powered alert analysis
- **Phase 4** (Complete): Active Response - DNS blocking, device quarantine, playbooks
- **Phase 5** (Complete): Polish & Extensions
  - Ollama LLM monitoring
  - Performance optimization (connection pooling, caching)
  - Security hardening (rate limiting, password validation)
  - Documentation (deployment guide, user guide)
  - Endpoint agent for workstation monitoring
  - NetFlow/sFlow network flow support

## License

MIT

## Contributing

See [docs/implementation-status.md](docs/implementation-status.md) for current implementation status and remaining tasks.
