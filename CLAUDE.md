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

### Local Development (Windows with Podman/WSL)

The backend requires PostgreSQL (TimescaleDB) and Redis. On Windows, use Podman with WSL:

```bash
# 1. Start Podman machine (if not already running)
podman machine start

# 2. If Podman SSH fails (common issue), run containers directly via WSL as root:
wsl -d podman-machine-default -u root -- podman run -d --name netguardian-db \
  -e POSTGRES_USER=netguardian \
  -e POSTGRES_PASSWORD=netguardian-dev-password \
  -e POSTGRES_DB=netguardian \
  -p 5432:5432 timescale/timescaledb:latest-pg16

wsl -d podman-machine-default -u root -- podman run -d --name netguardian-redis \
  -p 6379:6379 redis:7-alpine

# 3. Get WSL IP address
wsl -d podman-machine-default -- ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
# Example output: 172.27.3.179

# 4. Set up Windows port forwarding (run as Administrator)
netsh interface portproxy add v4tov4 listenport=5432 listenaddress=127.0.0.1 connectport=5432 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=6379 connectport=6379 connectaddress=<WSL_IP>

# 5. Verify port forwarding
netsh interface portproxy show all

# 6. Create backend/.env for local development
cat > backend/.env << 'EOF'
DATABASE_URL=postgresql+asyncpg://netguardian:netguardian-dev-password@localhost:5432/netguardian
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key-change-in-production-must-be-64-chars-hex
DEBUG=true
LOG_LEVEL=DEBUG
EOF

# 7. Run migrations and start servers
cd backend && alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
cd ../frontend && npm run dev &
```

**Note:** The WSL IP address can change on reboot. If connections fail, get the new IP and update port forwarding.

To clean up port forwarding:
```bash
netsh interface portproxy delete v4tov4 listenport=5432 listenaddress=127.0.0.1
netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1
```

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
2. **Services** (`app/services/`): Business logic (LLM, anomaly detection, playbooks, quarantine)
3. **Models** (`app/models/`): SQLAlchemy models with TimescaleDB hypertables for events
4. **Collectors** (`app/collectors/`): Data collection from various sources (API pull, file watch, UDP listener)
5. **Parsers** (`app/parsers/`): Log format parsers (AdGuard, syslog, JSON, Custom, NetFlow, sFlow, endpoint, Ollama)
6. **Events** (`app/events/`): Redis Streams event bus for async communication
7. **Core** (`app/core/`): Security, caching, rate limiting, validation, middleware utilities

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

- **AdGuard Home**: DNS-level device blocking
- **Router Integration**: UniFi, pfSense, OPNsense device quarantine
- **Anthropic Claude**: LLM-powered alert analysis and natural language queries
- **Ollama**: Local LLM monitoring for prompt injection/jailbreak detection

## Testing

Tests are in `backend/tests/`. The test suite uses pytest with async support (`asyncio_mode = "auto"`). Current coverage: 256 tests.

Test organization mirrors the app structure:
- `tests/parsers/` - Parser unit tests
- `tests/collectors/` - Collector unit tests
- `tests/services/` - Service layer tests

## Configuration

Environment variables are defined in `deploy/.env`. Key settings:
- `SECRET_KEY`: JWT signing key (generate with `openssl rand -hex 32`)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `ANTHROPIC_API_KEY`: For LLM features
- `ADGUARD_*` / `ROUTER_*`: Integration settings
- `RATE_LIMIT_*`: API rate limiting settings
- `SMTP_*` / `NTFY_*`: Notification settings

See `docs/configuration.md` for complete reference.

## Important Files

### Core Modules
- `app/core/middleware.py` - MetricsMiddleware, RequestLoggingMiddleware
- `app/core/rate_limiter.py` - Token bucket rate limiting
- `app/core/cache.py` - Redis caching layer
- `app/collectors/error_handler.py` - Retry logic, circuit breaker

### Key API Endpoints
- `app/api/v1/metrics.py` - Prometheus metrics (`/api/v1/metrics`)
- `app/api/v1/topology.py` - Network topology visualization
- `app/api/v1/threat_intel.py` - Threat intelligence feeds
- `app/api/v1/rules.py` - Custom detection rules

### CI/CD
- `.github/workflows/ci.yml` - Continuous integration
- `.github/workflows/release.yml` - Release automation
