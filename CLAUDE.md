# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

### Docker/Podman Deployment

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
5. **Parsers** (`app/parsers/`): Log format parsers (AdGuard, syslog, JSON, NetFlow, sFlow, endpoint)
6. **Events** (`app/events/`): Redis Streams event bus for async communication
7. **Core** (`app/core/`): Security, caching, rate limiting, validation utilities

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

See `deploy/.env.example` for all options.
