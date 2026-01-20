# NetGuardian AI - Development Notes

Issues, gotchas, and lessons learned during development.

---

## Build & Deployment Issues

### Hatchling Build System

**Problem:** Build failed with "Readme file does not exist: README.md"

**Cause:** Hatchling (the build backend in pyproject.toml) requires a README.md file by default.

**Solution:** Created `backend/README.md` with basic project description.

**Also needed:** Added explicit package configuration to pyproject.toml:
```toml
[tool.hatch.build.targets.wheel]
packages = ["app"]
```

---

### NPM CI vs NPM Install

**Problem:** Frontend Docker build failed - `npm ci` requires package-lock.json

**Cause:** The Dockerfile used `npm ci` but no package-lock.json was committed.

**Solution:** Changed Dockerfile to use `npm install` instead:
```dockerfile
RUN npm install
```

**Alternative:** Could commit package-lock.json, but npm install is more flexible for development.

---

### Tailwind CSS Color Scales

**Problem:** Build error "The `text-success-700` class does not exist"

**Cause:** Tailwind's custom color configuration only had partial scales (e.g., just 500, 600).

**Solution:** Extended all custom colors with full 50-900 scales in tailwind.config.js:
```javascript
success: {
  50: '#f0fdf4',
  100: '#dcfce7',
  // ... full scale
  900: '#14532d',
},
```

---

## Python/Backend Issues

### Structlog with PrintLoggerFactory

**Problem:** `AttributeError: 'PrintLogger' object has no attribute 'name'`

**Cause:** Using stdlib-specific processors (`add_logger_name`, `PositionalArgumentsFormatter`) with `PrintLoggerFactory`.

**Solution:** Removed stdlib-specific processors, used structlog's native processors:
```python
shared_processors = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,  # Not stdlib.add_log_level
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.UnicodeDecoder(),
]
```

---

### SQLAlchemy 2.0 Raw SQL

**Problem:** `Not an executable object: 'SELECT 1'`

**Cause:** SQLAlchemy 2.0 requires raw SQL to be wrapped in `text()`.

**Solution:**
```python
from sqlalchemy import text

async with engine.begin() as conn:
    await conn.execute(text("SELECT 1"))
```

---

### Passlib BCrypt Issue

**Problem:** `ValueError: password cannot be longer than 72 bytes` during bcrypt detection test

**Cause:** Passlib's bcrypt wrapper runs a self-test on import that was failing in the container environment.

**Solution:** Replaced passlib with direct bcrypt usage:
```python
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
```

---

### SQLAlchemy Enum Values vs Names

**Problem:** `invalid input value for enum userrole: "ADMIN"`

**Cause:** SQLAlchemy's `Enum` type uses Python enum member names (ADMIN) by default, but PostgreSQL enum was created with values (admin).

**Solution:** Added `values_callable` to use enum values:
```python
role: Mapped[UserRole] = mapped_column(
    SQLEnum(UserRole, name="userrole", values_callable=lambda x: [e.value for e in x]),
    default=UserRole.VIEWER,
    nullable=False,
)
```

---

### Settings Attribute Case

**Problem:** `Settings object has no attribute 'REDIS_URL'`

**Cause:** Pydantic settings uses lowercase attribute names by default.

**Solution:** Use lowercase: `settings.redis_url` not `settings.REDIS_URL`

---

## Frontend Issues

### Login Not Returning User

**Problem:** User logged in but role check failed - always showed "non-admin" UI

**Cause:** Backend login endpoint only returned tokens, not user object. Frontend expected `data.user` in response.

**Solution:** Updated backend to return `LoginResponse` that includes user:
```python
class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse
```

---

### Zustand Persistence and Stale Data

**Problem:** After fixing login response, old cached data persisted

**Cause:** Zustand with `persist` middleware stores state in localStorage

**Solution:** User needs to clear localStorage or the auth store when schema changes. Consider adding a version to the persisted state.

---

## Podman-Specific Issues

### Container Dependencies

**Problem:** Could not remove/restart containers due to dependencies

**Cause:** Podman manages container dependencies differently than Docker

**Solution:** Stop and remove dependent containers first, or use `--force`:
```bash
podman stop netguardian-collector netguardian-frontend netguardian-backend
podman rm -f netguardian-collector netguardian-frontend netguardian-backend
podman-compose up -d backend frontend collector
```

---

### Esbuild Permission Issue in Podman/WSL2

**Problem:** `spawn /app/node_modules/@esbuild/linux-x64/bin/esbuild EACCES` during frontend build

**Cause:** Podman with WSL2 backend strips execute permissions from node_modules binaries during the Docker build process.

**Solution:** Install a matching version of esbuild globally and use the `ESBUILD_BINARY_PATH` environment variable:
```dockerfile
# Install matching esbuild version globally to work around permission issues
RUN npm install -g esbuild@0.21.5

# Build the application (use global esbuild)
ENV ESBUILD_BINARY_PATH=/usr/local/bin/esbuild
RUN npm run build
```

**Note:** The esbuild version must match what vite expects (check in node_modules/esbuild/package.json).

---

### Nginx DNS Caching

**Problem:** 502 Bad Gateway after backend restart

**Cause:** Nginx caches DNS resolution. After backend container recreation, IP changed but nginx had old IP cached.

**Solution:** Restart nginx (frontend) container after backend changes:
```bash
podman restart netguardian-frontend
```

**Better solution:** Configure nginx with `resolver` directive for dynamic resolution.

---

### Database Volume Persistence

**Problem:** Database password mismatch after recreation

**Cause:** PostgreSQL stores credentials in the data volume. Changing `DB_PASSWORD` in .env doesn't update existing database.

**Solution:** Either:
1. Use same password as when volume was created
2. Remove volume and recreate: `podman volume rm netguardian-timescale-data`

---

### Shell Escaping in SQL Updates

**Problem:** Password hash got corrupted when updating via psql

**Cause:** `$` characters in bcrypt hash were interpreted by shell

**Solution:** Run password updates from within Python:
```python
podman exec netguardian-backend python -c "
from app.core.security import hash_password
# ... update via SQLAlchemy
"
```

---

## General Gotchas

### Multiple Uvicorn Workers

**Problem:** Init code (admin user creation) ran multiple times, causing unique constraint errors

**Cause:** Docker Compose starts uvicorn with `--workers 2`, each worker runs startup code

**Solution:** The init code checks for existing users before creating. Errors from race condition are caught and logged but don't prevent startup.

**Better solution:** Use a separate init container or database migration for one-time setup.

---

### TimescaleDB Hypertable Requirements

**Note:** Hypertables require a composite primary key that includes the partition column (timestamp).

```sql
sa.PrimaryKeyConstraint("id", "timestamp")  -- Both columns in PK
```

---

### Form Data vs JSON for Login

**Note:** OAuth2PasswordRequestForm expects `application/x-www-form-urlencoded` data, not JSON or multipart.

**Problem:** Using `FormData` with explicit `Content-Type: application/x-www-form-urlencoded` doesn't work because `FormData` always sends as `multipart/form-data`.

**Solution:** Use `URLSearchParams` which correctly serializes to URL-encoded format:

```javascript
// Correct - URLSearchParams
const params = new URLSearchParams();
params.append('username', credentials.username);
params.append('password', credentials.password);
await apiClient.post('/auth/login', params, {
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
});

// Incorrect - FormData (sends as multipart/form-data)
const formData = new FormData();
formData.append('username', credentials.username);
formData.append('password', credentials.password);
await apiClient.post('/auth/login', formData);  // Wrong!

// Incorrect - JSON
await apiClient.post('/auth/login', { username, password });  // Wrong!
```

---

## Performance Notes

- TimescaleDB hypertable uses 7-day chunks - good for home use
- Redis maxmemory set to 256mb with allkeys-lru policy
- SQLAlchemy pool_size=20, max_overflow=30 (configurable via env vars)
- HTTP client pooling via shared `HttpClientPool` for connection reuse
- Redis caching layer available via `CacheService` for list endpoints

### Connection Pool Configuration (Phase 5)

Database and HTTP client pools are now configurable:
```bash
# Database
DB_POOL_SIZE=20           # Persistent connections
DB_MAX_OVERFLOW=30        # Extra connections
DB_POOL_TIMEOUT=30        # Wait time (seconds)
DB_POOL_RECYCLE=1800      # Recycle after 30 min

# HTTP Client
HTTP_TIMEOUT_SECONDS=30
HTTP_MAX_CONNECTIONS=100
HTTP_KEEPALIVE_EXPIRY=30
```

---

## Phase 7 Notes

### Prometheus Metrics (Phase 7)

**Module:** `app/services/metrics_service.py`

Exposes metrics at `/api/v1/metrics` for Prometheus scraping. Metrics include:
- HTTP request counts and latency histograms
- WebSocket connection gauges
- Event processing counters
- Alert and anomaly metrics
- Device and collector metrics
- Threat intelligence metrics

**Middleware:** `app/core/middleware.py` - MetricsMiddleware automatically tracks all HTTP requests.

### Network Topology Visualization (Phase 7)

**Backend:** `app/api/v1/topology.py`
- Returns nodes (devices, router, internet) and links (connections)
- Calculates event counts per device for the time window
- Supports filtering by time window (1-168 hours)

**Frontend:** `pages/TopologyPage.tsx`
- Canvas-based force-directed graph using custom physics simulation
- Interactive: drag nodes, pan (right-click), zoom (scroll)
- Click nodes to view details in side panel

### Collector Error Handling (Phase 7)

**Module:** `app/collectors/error_handler.py`

Provides robust error handling for collectors:
- **ErrorCategory** enum: network, auth, rate_limit, server, client, parse, config, resource
- **RetryHandler**: Exponential backoff with jitter
- **CircuitBreaker**: Prevents overwhelming failed services (closed → open → half_open states)
- **ErrorTracker**: Monitors error rates and history

**Usage in API Pull Collector:**
```python
self._retry_handler = RetryHandler(retry_config, self._circuit_breaker)
response = await self._retry_handler.execute(self._make_request, self.source_id, "api_poll")
```

**Configurable via source config:**
- `max_retries`: Number of retry attempts (default: 3)
- `retry_initial_delay`: Initial delay in seconds (default: 1.0)
- `retry_max_delay`: Maximum delay cap (default: 60.0)
- `circuit_failure_threshold`: Failures before opening circuit (default: 5)
- `circuit_recovery_timeout`: Seconds before testing recovery (default: 30)

### API Rate Limiting (Phase 7)

**Module:** `app/core/rate_limiter.py`

Token bucket rate limiting with per-endpoint categories:
- `auth`: 10 requests/minute (login, password reset)
- `chat`: 20 requests/minute (LLM chat endpoints)
- `export`: 5 requests/minute (CSV/PDF exports)
- `default`: 60 requests/minute (all other endpoints)

**Headers returned:**
- `X-RateLimit-Limit`: Requests allowed per minute
- `X-RateLimit-Remaining`: Requests remaining in window
- `X-RateLimit-Reset`: Unix timestamp when window resets
- `Retry-After`: Seconds to wait (when rate limited)

**Excluded paths:** `/health`, `/metrics`, `/docs`, `/redoc`, `/openapi.json`

### CI/CD Pipeline (Phase 7)

**GitHub Actions workflows:**

**ci.yml** - Runs on push/PR to main/develop:
- Backend lint (Ruff), type check (mypy), tests with coverage
- Frontend lint (ESLint), build (TypeScript + Vite)
- Docker image builds
- Security scan (Bandit, Safety)

**release.yml** - Runs on version tags (v*):
- Multi-platform Docker builds (amd64, arm64)
- Push to GitHub Container Registry
- Automatic changelog generation
- GitHub Release creation

---

## Security Notes

- JWT secret key should be 64+ character hex string in production
- Never log passwords or full JWT tokens
- Admin password only shown once in logs on first startup
- API keys for push sources should be treated as secrets

### Security Hardening (Phase 5)

**Login Rate Limiting:**
- 5 login attempts per minute
- 5-minute block after exceeding limit
- Rate limit reset on successful login

**Password Requirements:**
- Minimum 12 characters
- Mixed case (upper + lower)
- At least one digit
- At least one special character
- Not a common password
- No 3+ consecutive identical characters

**Startup Security Checks:**
The application warns at startup about:
- Default/weak SECRET_KEY
- DEBUG mode enabled
- Wildcard CORS origins
- Weak database passwords
- Long JWT expiration times
- Missing API keys

**New Security Modules:**
- `app/core/rate_limit.py` - Rate limiting utilities
- `app/core/validation.py` - Input validation and sanitization

---

## Collector Worker Notes

### Auto-Registration Pattern

**Problem:** Collectors and parsers weren't being registered despite decorator usage

**Cause:** Python modules with decorators need to be imported for the decorators to execute

**Solution:** Updated `__init__.py` files to import all collector/parser modules:
```python
# app/collectors/__init__.py
from app.collectors import api_pull_collector  # noqa: F401
from app.collectors import file_collector  # noqa: F401

# app/parsers/__init__.py
from app.parsers import json_parser  # noqa: F401
from app.parsers import syslog_parser  # noqa: F401
from app.parsers import adguard_parser  # noqa: F401
from app.parsers import custom_parser  # noqa: F401
```

---

### ParseResult Types

**Note:** The `ParseResult` dataclass uses enum types directly from `raw_event.py`:
- `event_type: EventType` (not string)
- `severity: EventSeverity` (not string)

Parsers should return enum values, not strings:
```python
return ParseResult(
    event_type=EventType.DNS,  # Not "dns"
    severity=EventSeverity.INFO,  # Not "info"
    ...
)
```

---

### Database Volume After Changes

**Problem:** After `podman-compose down && up`, database authentication fails

**Cause:** The database volume persists even when containers are recreated. If the password in `.env` is different from when the volume was created, authentication fails.

**Solution:** Remove the volume to reset the database:
```bash
podman stop -a && podman rm -a
podman volume rm netguardian-timescale-data
podman-compose up -d
# Don't forget to run migrations!
podman exec netguardian-backend alembic upgrade head
```
