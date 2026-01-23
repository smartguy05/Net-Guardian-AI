# NetGuardian AI

AI-powered home network security monitoring system with multi-source log collection, device inventory, anomaly detection, LLM-assisted threat analysis, and automated response capabilities.

## Current Status: Phase 7 (Technical Debt & DevOps) - COMPLETE

All phases complete! The system provides comprehensive network security monitoring with:
- Multi-source log collection (API, file, push, UDP flow data)
- Device inventory with auto-discovery and network topology visualization
- Anomaly detection with behavioral baselines
- LLM-powered threat analysis (Claude integration)
- Active response (device quarantine via AdGuard/router)
- Two-factor authentication (TOTP) and dark mode
- Real-time WebSocket updates and push notifications
- Threat intelligence feed integration
- Prometheus metrics and CI/CD pipeline

## Features

### Core Features
- **Multi-Source Log Collection** - API polling, file watching, HTTP push, UDP (NetFlow/sFlow), Grafana Loki
- **Device Inventory** - Auto-discovery with network topology visualization
- **Real-time Event Processing** - Redis Streams event bus with WebSocket updates
- **Authentication & RBAC** - JWT tokens, 2FA (TOTP), admin/operator/viewer roles
- **Dashboard** - Device list, event feed, alerts, stats overview
- **TimescaleDB** - Time-series optimized storage for events
- **Dark Mode** - Full dark theme support

### Detection & Analysis
- **Anomaly Detection** - Behavioral baselines with statistical detection
- **LLM Integration** - Claude-powered alert analysis and natural language queries
- **Threat Intelligence** - Feed integration for IP/domain/URL indicators
- **Custom Detection Rules** - Visual rule builder for custom alerts
- **Ollama LLM Monitoring** - Detect prompt injection, jailbreaks, LLM-malware

### Response & Automation
- **Active Response** - AdGuard Home and router-level device quarantine
- **Response Playbooks** - Automated action chains with configurable triggers
- **Notifications** - Email (SMTP) and push notifications (ntfy.sh)
- **Data Retention** - Configurable auto-purge policies

### Operations
- **Prometheus Metrics** - `/metrics` endpoint for monitoring
- **API Rate Limiting** - Token bucket rate limiting per endpoint
- **Audit Logging** - Full security event audit trail
- **CSV/PDF Export** - Export events, alerts, devices to various formats
- **CI/CD Pipeline** - GitHub Actions for testing and releases

## Quick Start

### Prerequisites
- **Linux/macOS**: Docker or Podman, Python 3.11+, Node.js 18+
- **Windows**: Podman Desktop (with WSL2), Python 3.11+, Node.js 18+
- 2GB RAM minimum

### Development Setup (Recommended)

The easiest way to run NetGuardian AI for development:

**Linux/macOS:**
```bash
# Make scripts executable (first time only)
chmod +x scripts/*.sh

# Start everything (containers + backend + frontend)
./scripts/start-dev.sh

# Or start with demo data pre-loaded
./scripts/start-dev.sh --seed-data
```

**Windows (PowerShell as Administrator):**
```powershell
# Start everything
.\scripts\start-dev.ps1

# Or start with demo data pre-loaded
.\scripts\start-dev.ps1 -SeedData
```

### Access

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |

### Default Login

On first startup, an admin user is created with a randomly generated password. Check the terminal output for:
```
INITIAL ADMIN USER CREATED
Username: admin
Password: <random-password>
```

### Demo Data

To load demo data for testing (17 devices, 380+ events, alerts, etc.):

```bash
# Linux/macOS
./scripts/start-dev.sh --seed-data

# Windows
.\scripts\start-dev.ps1 -SeedData

# Or manually after startup
cd backend && python scripts/seed_demo_data.py
```

**Demo Credentials:**
| User | Password | Role |
|------|----------|------|
| demo_admin | DemoAdmin123! | Admin |
| demo_operator | DemoOp123! | Operator |
| demo_viewer | DemoView123! | Viewer |

### Production Deployment

For production, use Docker/Podman Compose:

```bash
cd deploy
cp .env.example .env  # Edit with your settings
docker-compose up -d  # or podman-compose
docker exec netguardian-backend alembic upgrade head
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
│   │   └── core/            # Security, caching, rate limiting, middleware
│   ├── alembic/             # Database migrations
│   └── tests/               # Backend tests
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── pages/           # Page components
│   │   ├── stores/          # Zustand state stores
│   │   └── api/             # API client and hooks
│   └── public/
├── agent/                   # Optional endpoint agent
│   ├── netguardian_agent.py # Standalone monitoring agent
│   ├── agent_config.yaml.example
│   └── requirements.txt
├── scripts/
│   ├── start-dev.sh          # Linux/macOS startup script
│   ├── start-dev.ps1         # Windows startup script
│   ├── stop-dev.sh           # Linux/macOS stop script
│   ├── stop-dev.ps1          # Windows stop script
│   └── seed_demo_data.py     # Demo data seeder (in backend/scripts/)
├── deploy/
│   ├── docker-compose.yml
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── .env.example
├── .github/
│   └── workflows/           # CI/CD pipelines
│       ├── ci.yml           # Continuous integration
│       └── release.yml      # Release automation
├── docs/
│   ├── configuration.md     # Configuration reference
│   ├── deployment-guide.md  # Deployment documentation
│   ├── user-guide.md        # End-user documentation
│   └── prd.md               # Product requirements
├── CONTRIBUTING.md          # Contribution guidelines
└── CLAUDE.md                # Claude Code guidance
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

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_RPM=60    # Requests per minute

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

# Notifications - optional
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=app-password

NTFY_SERVER_URL=https://ntfy.sh
NTFY_DEFAULT_TOPIC=my-netguardian
```

See [Configuration Reference](docs/configuration.md) for full documentation.

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

### Development Scripts

Scripts are provided for easy development setup on both Linux and Windows.

| Script | Linux/macOS | Windows (PowerShell) |
|--------|-------------|----------------------|
| Start all | `./scripts/start-dev.sh` | `.\scripts\start-dev.ps1` |
| Start + demo data | `./scripts/start-dev.sh --seed-data` | `.\scripts\start-dev.ps1 -SeedData` |
| Use Docker | `./scripts/start-dev.sh --docker` | N/A (uses Podman) |
| Stop servers | `./scripts/stop-dev.sh` | `.\scripts\stop-dev.ps1` |
| Stop all | `./scripts/stop-dev.sh --stop-containers` | `.\scripts\stop-dev.ps1 -StopContainers` |

**First time on Linux/macOS:**
```bash
chmod +x scripts/*.sh
```

**Windows users:** Run PowerShell as Administrator, or double-click `start-netguardian.bat`.

### What the Scripts Do

1. Start database (TimescaleDB) and Redis containers
2. Set up port forwarding (Windows only - for WSL)
3. Create `backend/.env` if it doesn't exist
4. Run database migrations
5. Optionally seed demo data
6. Start backend (port 8000) and frontend (port 5173)

### Manual Setup

If you prefer to run things manually:

**1. Start containers:**
```bash
# Linux (Podman)
podman run -d --name netguardian-db -e POSTGRES_USER=netguardian \
  -e POSTGRES_PASSWORD=netguardian-dev-password -e POSTGRES_DB=netguardian \
  -p 5432:5432 timescale/timescaledb:latest-pg16

podman run -d --name netguardian-redis -p 6379:6379 redis:7-alpine

# Or use Docker
docker run -d --name netguardian-db ...
```

**2. Create backend/.env:**
```bash
cat > backend/.env << 'EOF'
DATABASE_URL=postgresql+asyncpg://netguardian:netguardian-dev-password@localhost:5432/netguardian
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key-change-in-production-must-be-64-chars-hex
DEBUG=true
LOG_LEVEL=DEBUG
EOF
```

**3. Run backend:**
```bash
cd backend
pip install -e .
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

**4. Run frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Windows/Podman Notes

Podman on Windows uses WSL2 and sometimes has SSH tunnel issues. The startup script handles this automatically by:
- Running containers via WSL directly (`wsl -d podman-machine-default -u root -- podman ...`)
- Setting up Windows port forwarding to the WSL IP address

If you need to manually fix port forwarding after a reboot:
```powershell
# Get new WSL IP
wsl -d podman-machine-default -- ip addr show eth0 | Select-String "inet "

# Update port forwarding (as Administrator)
netsh interface portproxy delete v4tov4 listenport=5432 listenaddress=127.0.0.1
netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1
netsh interface portproxy add v4tov4 listenport=5432 listenaddress=127.0.0.1 connectport=5432 connectaddress=<NEW_IP>
netsh interface portproxy add v4tov4 listenport=6379 listenaddress=127.0.0.1 connectport=6379 connectaddress=<NEW_IP>
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

All planned phases are complete!

- **Phase 1** (Complete): Foundation - Multi-source collection, device inventory, dashboard
- **Phase 2** (Complete): Anomaly Detection - Behavioral baselines, statistical detection
- **Phase 3** (Complete): LLM Integration - Claude-powered alert analysis
- **Phase 4** (Complete): Active Response - DNS blocking, device quarantine, playbooks
- **Phase 5** (Complete): Polish & Extensions - Ollama monitoring, endpoint agent, NetFlow/sFlow
- **Phase 6** (Complete): Feature Enhancements
  - Dark mode theme
  - WebSocket real-time updates
  - Email and ntfy.sh notifications
  - Two-factor authentication (2FA/TOTP)
  - Data retention policies
  - CSV/PDF export
  - Device tagging UI
  - Custom detection rules UI
  - Threat intelligence feed integration
- **Phase 7** (Complete): Technical Debt & DevOps
  - Prometheus metrics endpoint
  - Network topology visualization
  - Collector error handling with retry logic and circuit breakers
  - API rate limiting
  - CI/CD pipeline (GitHub Actions)
  - Configuration and contributing documentation

## Monitoring

### Prometheus Metrics

NetGuardian exposes Prometheus metrics at `/api/v1/metrics`:

```bash
curl http://localhost:8000/api/v1/metrics
```

Available metrics include:
- `http_requests_total` - HTTP request counts by method, endpoint, status
- `http_request_duration_seconds` - Request latency histogram
- `events_processed_total` - Events processed by type and source
- `alerts_active` - Active alerts by severity
- `devices_total` - Device counts by status
- `collector_errors_total` - Collector errors by type

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.
