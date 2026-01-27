# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL: Memory Files

**ALWAYS update the `.memories/` directory files when relevant.** These files track project state across sessions:

| File | Purpose | When to Update |
|------|---------|----------------|
| `.memories/completed.md` | Completed tasks by phase | When finishing ANY task, feature, or fix |
| `.memories/todos.md` | Remaining tasks and tech debt | When adding, completing, or deprioritizing tasks |
| `.memories/notes.md` | Issues, gotchas, lessons learned | When encountering bugs, workarounds, or patterns |

**Rules:**
1. Update these files **AT ALL TIMES** - they are the project's memory
2. Update `completed.md` immediately after finishing a task (not at end of session)
3. Update `todos.md` to check off completed items and add new discovered tasks
4. Update `notes.md` with any issue you debug/solve that others might hit
5. Keep entries concise but descriptive - future you needs to understand

## Project Overview

NetGuardian AI is an AI-powered home network security monitoring system with multi-source log collection, device inventory, anomaly detection, LLM-assisted threat analysis, and automated response capabilities.

## Common Commands

### Backend (Python/FastAPI)

```bash
cd backend

# Install dependencies
pip install -e ".[dev]"

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/parsers/test_adguard_parser.py -v

# Run tests matching pattern
pytest -k "test_anomaly" -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html

# Linting
ruff check app/ tests/

# Type checking
mypy app/
```

### Frontend (React/TypeScript)

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Build (includes TypeScript check)
npm run build

# Lint
npm run lint
```

### Quick Start with Scripts (Recommended)

Use the startup scripts in `scripts/` to automate the entire development environment setup:

```powershell
# Start everything (containers, migrations, backend, frontend)
.\scripts\start-dev.ps1

# Start with demo data loaded
.\scripts\start-dev.ps1 -SeedData

# Start only backend/frontend (containers already running)
.\scripts\start-dev.ps1 -SkipContainers

# Stop all servers
.\scripts\stop-dev.ps1

# Stop servers and containers
.\scripts\stop-dev.ps1 -StopContainers

# Stop everything and clean up port forwarding
.\scripts\stop-dev.ps1 -StopContainers -CleanPortForwarding
```

**Demo Credentials** (when using `-SeedData`):
- Admin: `demo_admin` / `DemoAdmin123!`
- Operator: `demo_operator` / `DemoOp123!`
- Viewer: `demo_viewer` / `DemoView123!`

**What the scripts do:**
1. Start Podman machine and containers (TimescaleDB, Redis)
2. Configure Windows port forwarding for WSL
3. Create `backend/.env` if missing
4. Run database migrations
5. Start backend (uvicorn) and frontend (vite) servers

### Manual Local Development (Windows with Podman/WSL)

If you need manual control, the backend requires PostgreSQL (TimescaleDB) and Redis. On Windows, use Podman with WSL:

```bash
# 1. Start Podman machine (if not already running)
podman machine start

# 2. Run containers via WSL as root:
wsl -d podman-machine-default -u root -- podman run -d --name netguardian-db \
  -e POSTGRES_USER=netguardian \
  -e POSTGRES_PASSWORD=netguardian-dev-password \
  -e POSTGRES_DB=netguardian \
  -p 5432:5432 timescale/timescaledb:latest-pg16

wsl -d podman-machine-default -u root -- podman run -d --name netguardian-redis \
  -p 6379:6379 redis:7-alpine

# 3. Get WSL IP and set up port forwarding (run as Administrator)
$wslIp = wsl -d podman-machine-default -- ip addr show eth0 | Select-String "inet " | ForEach-Object { ($_ -split '\s+')[2] -replace '/.*', '' }
netsh interface portproxy add v4tov4 listenport=5432 listenaddress=127.0.0.1 connectport=5432 connectaddress=$wslIp
netsh interface portproxy add v4tov4 listenport=6379 listenaddress=127.0.0.1 connectport=6379 connectaddress=$wslIp

# 4. Run migrations and start servers
cd backend && alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# In another terminal:
cd frontend && npm run dev
```

**Note:** The WSL IP address can change on reboot. Use `.\scripts\start-dev.ps1` which handles this automatically.

### Docker/Podman Deployment (Production)

```bash
cd deploy

# Start all services
podman-compose up -d  # or docker-compose

# Run database migrations
podman exec netguardian-backend alembic upgrade head

# View logs
podman logs netguardian-backend

# Initial admin password
podman logs netguardian-backend | grep "Initial admin"
```

### Database Migrations (Alembic)

```bash
cd backend

# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1
```

## Architecture

### Container Services

- **backend** (port 8000): FastAPI application
- **frontend** (port 5173): React app served via Nginx
- **db** (port 5432): TimescaleDB (PostgreSQL 16 with time-series extensions)
- **redis** (port 6379): Redis Streams for event bus and caching
- **collector**: Background worker for log collection

### Backend Structure

The backend uses a layered architecture:

1. **API Layer** (`app/api/v1/`): REST endpoints with FastAPI routers
2. **Services** (`app/services/`): Business logic (LLM, anomaly detection, playbooks, quarantine, semantic analysis)
   - `llm_providers/`: Modular LLM provider implementations (Claude, Ollama)
   - `integrations/`: Router integrations (AdGuard, UniFi, pfSense)
3. **Models** (`app/models/`): SQLAlchemy models with TimescaleDB hypertables for events
4. **Collectors** (`app/collectors/`): Data collection from various sources (API pull, file watch, UDP listener)
5. **Parsers** (`app/parsers/`): Log format parsers (AdGuard, syslog, JSON, Custom, NetFlow, sFlow, endpoint, Ollama, Loki)
6. **Events** (`app/events/`): Redis Streams event bus for async communication
7. **Core** (`app/core/`): Security, caching, rate limiting, validation, middleware utilities
8. **Database** (`app/db/`): Session management and repositories

### Key Patterns

**Collector/Parser Registration**: Collectors and parsers use decorator-based registration:
```python
@register_collector(SourceType.API_PULL)
class APIPullCollector(BaseCollector): ...

@register_parser("adguard")
class AdGuardParser(BaseParser): ...
```

**SQLAlchemy Enums**: Use `values_callable` for PostgreSQL enum compatibility:
```python
role: Mapped[UserRole] = mapped_column(
    SQLEnum(UserRole, name="userrole", values_callable=lambda x: [e.value for e in x]),
)
```

**Async Database Sessions**: Use `AsyncSession` with dependency injection:
```python
async def endpoint(session: Annotated[AsyncSession, Depends(get_async_session)]):
```

**Collector Error Handling**: Use RetryHandler and CircuitBreaker for robust collection:
```python
from app.collectors.error_handler import RetryHandler, CircuitBreaker, RetryConfig

retry_handler = RetryHandler(RetryConfig(max_retries=3), CircuitBreaker())
result = await retry_handler.execute(fetch_func, source_id, "operation_name")
```

**Rate Limiting**: API endpoints are automatically rate limited via middleware. For custom limits:
```python
from app.core.rate_limiter import rate_limit

@router.get("/expensive")
@rate_limit(requests_per_minute=5)
async def expensive_endpoint(request: Request):
    ...
```

### Data Flow

1. **Collection**: Collectors (API pull, file watch, UDP) fetch raw logs
2. **Parsing**: Parsers normalize logs into `RawEvent` records
3. **Storage**: Events stored in TimescaleDB hypertable (7-day chunks)
4. **Processing**: Worker associates events with devices, publishes to Redis
5. **Analysis**: Anomaly detection compares against device baselines
6. **Response**: Playbooks trigger actions (quarantine, alerts, webhooks)

### Integration Points

- **AdGuard Home**: DNS-level device blocking (`app/services/integrations/adguard.py`)
- **Router Integration**: UniFi, pfSense, OPNsense device quarantine (`app/services/integrations/`)
- **Authentik SSO**: OAuth2/OIDC Single Sign-On authentication (`app/services/oidc_service.py`)
- **Authentik Events**: Authentication event log parsing (`app/parsers/authentik_parser.py`)
- **Anthropic Claude**: LLM-powered alert analysis and natural language queries (`app/services/llm_providers/claude_provider.py`)
- **Ollama**: Local LLM monitoring for prompt injection/jailbreak detection (`app/services/llm_providers/ollama_provider.py`)

### LLM Provider Architecture

The LLM system uses a factory pattern for provider abstraction (`app/services/llm_providers/`):
- `base.py`: Abstract base class defining the LLM interface
- `claude_provider.py`: Anthropic Claude implementation
- `ollama_provider.py`: Local Ollama implementation
- `factory.py`: Provider instantiation based on configuration

## Testing

Tests are in `backend/tests/`. The test suite uses pytest with async support (`asyncio_mode = "auto"`). Current coverage: 488 tests.

Test organization mirrors the app structure:
- `tests/parsers/` - Parser unit tests
- `tests/collectors/` - Collector unit tests
- `tests/services/` - Service layer tests
- `tests/api/` - API endpoint tests
- `tests/integration/` - Integration tests
- `tests/factories/` - Test data factories

## Configuration

Environment variables are defined in `deploy/.env` and `backend/.env`. Key settings:

### Core Settings
- `SECRET_KEY`: JWT signing key (generate with `openssl rand -hex 32`)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `DEBUG`: Enable debug mode (default: false)
- `LOG_LEVEL`: Logging level (default: INFO)

### Database Pool Settings
- `DB_POOL_SIZE`: Persistent connections (default: 20)
- `DB_MAX_OVERFLOW`: Extra connections (default: 30)
- `DB_POOL_TIMEOUT`: Wait time in seconds (default: 30)
- `DB_POOL_RECYCLE`: Recycle after N seconds (default: 1800)

### LLM Configuration
- `ANTHROPIC_API_KEY`: For Claude-based LLM features
- `LLM_MODEL_DEFAULT`: Default model for analysis (default: claude-sonnet-4-latest)
- `LLM_MODEL_FAST`: Fast model for triage (default: claude-3-5-haiku-latest)
- `LLM_MODEL_DEEP`: Deep analysis model (default: claude-sonnet-4-latest)
- `LLM_ENABLED`: Enable LLM features (default: true)
- `LLM_CACHE_ENABLED`: Enable Anthropic prompt caching (default: true)

### Ollama Configuration
- `OLLAMA_ENABLED`: Enable local Ollama (default: false)
- `OLLAMA_URL`: Ollama API URL (default: http://localhost:11434)
- `OLLAMA_DEFAULT_MODEL`: Model for semantic analysis (default: llama3.2)
- `OLLAMA_DETECTION_ENABLED`: Enable injection detection (default: true)

### Semantic Analysis
- `SEMANTIC_ANALYSIS_ENABLED`: Enable semantic log analysis (default: true)
- `SEMANTIC_DEFAULT_LLM_PROVIDER`: "claude" or "ollama" (default: claude)
- `SEMANTIC_DEFAULT_RARITY_THRESHOLD`: Patterns < N are rare (default: 3)
- `SEMANTIC_SCHEDULER_ENABLED`: Enable automatic scheduling (default: true)

### Rate Limiting
- `RATE_LIMIT_ENABLED`: Enable rate limiting (default: true)
- `RATE_LIMIT_DEFAULT_RPM`: Default requests/minute (default: 60)
- `RATE_LIMIT_AUTH_RPM`: Auth endpoint limit (default: 10)
- `RATE_LIMIT_CHAT_RPM`: Chat endpoint limit (default: 20)
- `RATE_LIMIT_EXPORT_RPM`: Export endpoint limit (default: 5)

### Integrations
- `ADGUARD_*`: AdGuard Home integration (url, username, password, verify_ssl)
- `ROUTER_*`: Router integration (type, url, credentials, site)
- `AUTHENTIK_*`: Authentik SSO (enabled, issuer_url, client_id, client_secret, redirect_uri, group_mappings, auto_create_users, default_role)
- `SMTP_*`: Email notifications (host, port, username, password, use_tls)
- `NTFY_*`: Push notifications (server_url, topic, auth_token)

See `docs/configuration.md` for complete reference.

## Important Files

### Core Modules
- `app/core/middleware.py` - MetricsMiddleware, RequestLoggingMiddleware
- `app/core/rate_limiter.py` - Token bucket rate limiting
- `app/core/rate_limit.py` - Rate limiting utilities
- `app/core/cache.py` - Redis caching layer
- `app/core/security.py` - Authentication, password hashing, JWT handling
- `app/core/validation.py` - Input validation and sanitization
- `app/core/http_client.py` - Shared HTTP client pool
- `app/collectors/error_handler.py` - Retry logic, circuit breaker

### Key API Endpoints
- `app/api/v1/router.py` - Main router aggregating all endpoints
- `app/api/v1/auth.py` - Authentication (login, refresh, password reset)
- `app/api/v1/devices.py` - Device management and quarantine
- `app/api/v1/events.py` - Event queries and filtering
- `app/api/v1/alerts.py` - Alert management
- `app/api/v1/rules.py` - Custom detection rules
- `app/api/v1/semantic.py` - Semantic log analysis
- `app/api/v1/chat.py` - LLM chat interface
- `app/api/v1/topology.py` - Network topology visualization
- `app/api/v1/threat_intel.py` - Threat intelligence feeds
- `app/api/v1/metrics.py` - Prometheus metrics (`/api/v1/metrics`)
- `app/api/v1/websocket.py` - Real-time WebSocket updates
- `app/api/v1/playbooks.py` - Automated response playbooks
- `app/api/v1/admin.py` - Admin functions (retention, system config)

### Key Services
- `app/services/llm_service.py` - LLM orchestration and analysis
- `app/services/anomaly_service.py` - Anomaly detection engine
- `app/services/baseline_service.py` - Device behavior baselines
- `app/services/semantic_analysis_service.py` - Semantic log analysis
- `app/services/semantic_scheduler.py` - Scheduled analysis jobs
- `app/services/rule_suggestion_service.py` - AI-powered rule suggestions
- `app/services/pattern_service.py` - Log pattern extraction
- `app/services/playbook_engine.py` - Automated response execution
- `app/services/quarantine_service.py` - Device quarantine management
- `app/services/threat_intel_service.py` - Threat intelligence processing
- `app/services/metrics_service.py` - Prometheus metrics collection

### Database Models
- `app/models/device.py` - Network devices
- `app/models/raw_event.py` - Event hypertable (TimescaleDB)
- `app/models/alert.py` - Security alerts
- `app/models/anomaly.py` - Detected anomalies
- `app/models/detection_rule.py` - Custom detection rules
- `app/models/semantic_analysis.py` - Semantic analysis results
- `app/models/playbook.py` - Response playbooks
- `app/models/user.py` - Users and authentication

### CI/CD
- `.github/workflows/ci.yml` - Continuous integration
- `.github/workflows/release.yml` - Release automation

### Frontend Structure
The React frontend (`frontend/src/`) uses:
- **Pages** (`pages/`): Route components (Dashboard, Devices, Events, Alerts, Rules, etc.)
- **Components** (`components/`): Reusable UI components (modals, tables, forms)
- **API** (`api/`): API client and React Query hooks
- **Stores** (`stores/`): Zustand state management (auth, theme, help)
- **Hooks** (`hooks/`): Custom hooks (useWebSocket for real-time updates)
- **Types** (`types/`): TypeScript type definitions

Key frontend patterns:
- React Query for server state management
- Zustand for client state (auth persistence, theme)
- Tailwind CSS with dark mode support
- WebSocket for real-time event updates
