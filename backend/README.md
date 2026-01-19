# NetGuardian AI Backend

AI-Powered Home Network Security Monitoring System - Backend API

## Tech Stack

- **Python 3.12+** with FastAPI
- **TimescaleDB** (PostgreSQL 16 + time-series extensions)
- **Redis 7** for event bus and caching
- **SQLAlchemy 2.0** with async support
- **Alembic** for database migrations

## Project Structure

```
backend/
├── app/
│   ├── api/v1/          # REST API endpoints
│   ├── collectors/      # Log collection workers
│   ├── core/            # Core utilities (security, caching, rate limiting)
│   ├── db/              # Database session management
│   ├── events/          # Redis Streams event bus
│   ├── models/          # SQLAlchemy models
│   ├── parsers/         # Log format parsers
│   ├── schemas/         # Pydantic schemas
│   └── services/        # Business logic services
├── tests/               # Test suites
├── alembic/             # Database migrations
└── pyproject.toml       # Project configuration
```

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -e ".[dev]"

# Set up environment
cp ../.env.example ../.env
# Edit .env with your configuration

# Run migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/services/test_llm_service.py -v

# Run tests matching pattern
pytest -k "test_anomaly" -v
```

## API Documentation

When running in debug mode (`DEBUG=true`), API docs are available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Key Features

### Authentication & Authorization
- JWT-based authentication with access/refresh tokens
- Role-based access control (Admin, Operator, Viewer)
- Login rate limiting (5 attempts/minute)
- Password strength validation

### Data Collection
- API Pull collector (AdGuard, UniFi, custom APIs)
- File watcher for log files
- API Push endpoints for external log sources

### Anomaly Detection
- Per-device behavioral baselines
- DNS, traffic, and connection pattern analysis
- Statistical anomaly detection (z-score)

### LLM Integration
- Claude API integration for alert analysis
- Natural language network queries
- Incident summarization

### Active Response
- Device quarantine via AdGuard Home
- Router integration (UniFi, pfSense, OPNsense)
- Automated playbooks with triggers and actions
- Full audit logging

### Ollama Monitoring
- Prompt injection detection
- Jailbreak attempt detection
- Data exfiltration monitoring

## Environment Variables

See `.env.example` for all configuration options. Key variables:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing secret (min 32 chars) |
| `DATABASE_URL` | PostgreSQL connection URL |
| `REDIS_URL` | Redis connection URL |
| `ANTHROPIC_API_KEY` | Claude API key for LLM features |
| `DEBUG` | Enable debug mode (disable in production) |

## Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1

# Check current version
alembic current
```

## Code Quality

```bash
# Format code
black app/ tests/
isort app/ tests/

# Type checking
mypy app/

# Linting
ruff check app/ tests/
```

## Test Coverage

Current test coverage: **256 tests** covering:
- Collectors (API pull, file watch, UDP listener)
- Parsers (AdGuard, JSON, Syslog, Ollama, Endpoint, NetFlow, sFlow)
- Services (Baseline, Anomaly, LLM, Ollama)
- Integration services (AdGuard, UniFi, pfSense)
- Audit system
- Playbook engine
