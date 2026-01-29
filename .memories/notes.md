# NetGuardian AI - Development Notes

Issues, gotchas, and lessons learned during development.

---

## PostgreSQL Enum Migrations (January 2026)

**Problem:** Adding a new value to a SQLAlchemy Enum (like `SourceType.UDP_LISTEN`) requires a database migration. The Python enum is updated but PostgreSQL's `sourcetype` enum doesn't automatically get the new value.

**Error:** `asyncpg.exceptions.InvalidTextRepresentationError: invalid input value for enum sourcetype: "udp_listen"`

**Solution:** Create an Alembic migration to add the enum value:
```python
def upgrade() -> None:
    op.execute("ALTER TYPE sourcetype ADD VALUE IF NOT EXISTS 'udp_listen'")

def downgrade() -> None:
    # PostgreSQL doesn't support removing enum values directly
    pass
```

**Important:** Always create a migration when adding new enum values. Check `app/models/log_source.py` for `SourceType` and `ParserType` enums.

---

## Test Suite Gotchas (January 2026)

### FastAPI Query Parameter Defaults
**Problem:** When calling FastAPI endpoints directly in tests (without going through the ASGI test client), parameters with `Query(default)` become `Query` objects instead of the default values.

**Solution:** Always pass explicit values for Query parameters when testing endpoints directly:
```python
# Bad - limit becomes Query(1000) object
await export_devices_csv(session=session, _current_user=user)

# Good - explicit values
await export_devices_csv(session=session, _current_user=user, limit=1000, status_filter=None)
```

### MagicMock Attributes in Pydantic Models
**Problem:** When mocking database models, MagicMock returns MagicMock for any attribute access. This breaks Pydantic validation when building response models.

**Solution:** Explicitly set all attributes that will be accessed:
```python
alert = MagicMock()
alert.id = uuid4()
alert.device_id = None  # Prevents complex device queries
alert.acknowledged_at = None  # Must be None or datetime, not MagicMock
alert.resolved_at = None
```

### UDP Socket Tests on Windows
**Problem:** Tests that bind UDP ports fail with `PermissionError: [WinError 10013]` on Windows.

**Solution:** Mock `asyncio.get_running_loop().create_datagram_endpoint` instead of binding actual ports:
```python
with patch("asyncio.get_running_loop") as mock_loop:
    mock_loop.return_value.create_datagram_endpoint = AsyncMock(
        return_value=(mock_transport, mock_protocol)
    )
    await collector.start()
```

---

## Users Page Contrast Issues

**Problem:** Users page had poor contrast in dark mode - usernames, emails, role badges, and dropdown menu were hard to read.

**Fixed elements:**
- `roleColors` record (added dark variants with `/30` opacity backgrounds)
- Username (`text-gray-900` → `dark:text-white`)
- Email text (`dark:text-gray-400`)
- "You", "Inactive", "Must change password" badges
- Role badge in header section
- Dropdown menu (background, borders, hover states)
- Dropdown menu items and divider
- Temporary password notification box
- Page header and role legend text
- Loading skeletons
- Empty state

**File:** `frontend/src/pages/UsersPage.tsx`

---

## Sources Page Contrast Issues

**Problem:** Sources page had poor contrast in dark mode - source names were blue (hard to read), descriptions were too faint, and the API Key box had a white background.

**Fixed elements:**
- Source names (`text-gray-900` → `dark:text-white`)
- Descriptions (`text-gray-600` → `dark:text-gray-400`)
- Disabled badge (added dark mode variant)
- Type/Parser/Events/Last Event labels and values
- Error notification box
- API Key box (`bg-gray-50` → `dark:bg-zinc-900`)
- Copy button hover states
- Toggle buttons (Disable/Enable)
- Non-admin info box
- Loading skeletons
- Empty state

**File:** `frontend/src/pages/SourcesPage.tsx`

---

## Quarantine Page Theme Issues

**Problem:** Quarantine page had hardcoded light theme colors, making tables and UI elements appear white in dark mode.

**Fixed elements:**
- Header text (title and subtitle)
- Stats cards (icon backgrounds, text colors)
- Integration status cards (backgrounds, text, status indicators)
- Quarantined devices table (header, body, dividers, empty state)
- Recent activity table (all elements)
- QuarantinedDeviceRow component (hover states, text, badges)
- ActivityLogRow component (hover states, text, action badges)
- Sync results notification
- "View all audit logs" link

**File:** `frontend/src/pages/QuarantinePage.tsx`

---

## Anomalies Page Theme Issues

**Problem:** Anomalies page had hardcoded light theme colors, making the table and UI elements appear white/light in dark mode.

**Fixed elements:**
- Header text (`text-gray-900` → added `dark:text-white`)
- Stats cards (background, border, text colors)
- Filter section (background, border, select inputs)
- Table (header, body, rows, dividers)
- Severity badges (added dark mode variants with `/30` opacity backgrounds)
- Status badges (added dark mode variants)
- Action buttons (hover states)
- Detail modal (all sections)

**File:** `frontend/src/pages/AnomaliesPage.tsx`

---

## Topology Page Canvas Bug

**Problem:** Network map was clustered in the top-left corner instead of filling the container.

**Cause:** Multiple issues:
1. Canvas element didn't have CSS classes to fill its parent container
2. Node positions were initialized before canvas dimensions were set
3. Canvas dimensions were read directly from the element, which could be 0 initially

**Solution:**
1. Added `w-full h-full` CSS classes to the canvas element
2. Added `canvasSize` state to track dimensions reactively
3. Used `ResizeObserver` to detect container size changes
4. Updated node initialization to depend on `canvasSize` state
5. Made node radius calculation responsive to canvas size

**File:** `frontend/src/pages/TopologyPage.tsx`

---

## Phase 8 Notes

### Landing Page & Help System (Phase 8)

**Route Structure Change:**
- Landing page is now at `/` (public, no auth required)
- All authenticated dashboard routes moved under `/dashboard/*`
- Login redirects to `/dashboard` after successful authentication
- Navigation links in Layout.tsx updated to use `/dashboard` prefix

**Help Panel Implementation:**
- Uses Zustand store (`stores/help.ts`) for open/close state
- HelpButton is fixed positioned at bottom-right (z-40)
- HelpPanel slides from right edge with backdrop overlay
- Content is route-aware via `getHelpForPath()` function
- Keyboard shortcuts: `?` to toggle, `Esc` to close
- Excludes shortcuts when typing in input/textarea

**Theme Store Enhancement:**
- Added `resolvedTheme` to track actual theme (light/dark)
- Useful for components that need to know the effective theme
- System theme listener now updates `resolvedTheme` when preference changes

**Screenshot Fallbacks:**
- Landing page uses `onError` handler to display SVG placeholder
- Placeholder shows page name centered in gray box
- Actual screenshots should be placed in `/public/screenshots/`
- Naming convention: `{page}-{theme}.png` (e.g., `dashboard-dark.png`)

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

### Vite WebSocket Proxy Not Working

**Problem:** WebSocket connection to `ws://localhost:5173/api/v1/ws` fails with connection error. Console shows repeated WebSocket errors and disconnections.

**Cause:** Vite's proxy configuration doesn't proxy WebSocket connections by default. The frontend connects to the dev server port (5173), expecting Vite to forward to the backend (8000), but WebSocket upgrade requests weren't being handled.

**Solution:** Add `ws: true` to the Vite proxy configuration in `frontend/vite.config.ts`:
```typescript
proxy: {
  '/api': {
    target: 'http://localhost:8000',
    changeOrigin: true,
    ws: true,  // Enable WebSocket proxy
  },
},
```

**Note:** Must restart the Vite dev server after making this change.

---

### WebSocket Console Spam When Backend Unavailable

**Problem:** When backend is not running, WebSocket connection attempts flood the console with "WebSocket error" messages, potentially freezing the page.

**Cause:** The `useWebSocket` hook logged every error and attempted reconnection with a fixed 3-second interval. Combined with persisted auth state (user appears logged in from previous session), this created rapid error loops.

**Solution:** Updated `frontend/src/hooks/useWebSocket.ts` with:
1. **Single error logging**: Only log the first connection error via `hasLoggedErrorRef`
2. **Exponential backoff**: 3s → 6s → 12s → 24s → 48s instead of constant 3s
3. **Max retry tracking**: `maxRetriesExhaustedRef` stops attempts after max retries
4. **State reset on auth changes**: Fresh reconnection state when user logs in/out

**Key code pattern:**
```typescript
const hasLoggedErrorRef = useRef(false);
const maxRetriesExhaustedRef = useRef(false);

ws.onerror = (error) => {
  if (!hasLoggedErrorRef.current) {
    console.warn('WebSocket connection failed. Backend may be unavailable.');
    hasLoggedErrorRef.current = true;
  }
};

// Exponential backoff in onclose
const backoffDelay = reconnectInterval * Math.pow(2, reconnectAttemptsRef.current - 1);
```

---

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

### Podman Machine SSH Connection Failure on Windows

**Problem:** `podman machine start` reports "machine is not listening on ssh port" even though it says "already running". Commands like `podman ps` fail with "unable to connect to Podman socket".

**Cause:** The SSH tunnel between Windows and the WSL-based Podman machine fails to establish properly. The machine shows as "Currently running" but port forwarding is broken.

**Workaround:** Run Podman commands directly via WSL instead of relying on the SSH tunnel:

```bash
# Run containers as root in WSL
wsl -d podman-machine-default -u root -- podman run -d --name mycontainer -p 5432:5432 myimage

# Check running containers
wsl -d podman-machine-default -u root -- podman ps

# View logs
wsl -d podman-machine-default -u root -- podman logs mycontainer
```

**Note:** Using `-u root` is important because rootless podman in WSL often has issues with port binding and cgroups.

**WSL Port Forwarding:** Ports exposed in WSL containers aren't automatically accessible from Windows. Set up port forwarding:

```bash
# Get WSL IP
wsl -d podman-machine-default -- ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1

# Set up forwarding (run as Administrator)
netsh interface portproxy add v4tov4 listenport=5432 listenaddress=127.0.0.1 connectport=5432 connectaddress=<WSL_IP>

# Verify
netsh interface portproxy show all

# Delete when done
netsh interface portproxy delete v4tov4 listenport=5432 listenaddress=127.0.0.1
```

---

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

### Rollup Optional Dependency Not Installing (npm bug)

**Problem:** `Cannot find module @rollup/rollup-win32-x64-msvc` when running `npm run dev`

**Cause:** npm has a known bug with optional dependencies (https://github.com/npm/cli/issues/4828) where platform-specific packages aren't installed properly.

**Solution:** Manually download and extract the package:
```bash
cd frontend/node_modules/@rollup
npm pack @rollup/rollup-win32-x64-msvc@4.55.2
tar -xzf rollup-rollup-win32-x64-msvc-4.55.2.tgz
mv package rollup-win32-x64-msvc
rm rollup-rollup-win32-x64-msvc-4.55.2.tgz
```

**Note:** The version (4.55.2) must match what's in `node_modules/rollup/package.json` under `optionalDependencies`.

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

---

## API Data Format Mismatches

### Detection Rules response_actions Format

**Problem:** `/api/v1/rules` returning 500 Internal Server Error

**Cause:** Seed data stores `response_actions` as a list of strings (`["create_alert", "notify_admin"]`) but the API `RuleResponse` model expects `List[Dict[str, Any]]` (`[{"type": "create_alert", "config": {}}]`).

**Solution:** Added `_normalize_response_actions()` in `backend/app/api/v1/rules.py` that converts legacy string format to expected dict format:
```python
def _normalize_response_actions(actions: List[Any]) -> List[Dict[str, Any]]:
    normalized = []
    for action in actions:
        if isinstance(action, str):
            normalized.append({"type": action, "config": {}})
        elif isinstance(action, dict):
            if "config" not in action:
                action["config"] = {}
            normalized.append(action)
    return normalized
```

**File:** `backend/app/api/v1/rules.py:152-168`

---

### ThreatIndicator metadata vs extra_data

**Problem:** `/api/v1/threat-intel/indicators` returning 500 Internal Server Error

**Cause:** The `ThreatIndicator` model has a column named `extra_data` (JSONB), but the API code was accessing `ind.metadata`. Since `metadata` is a reserved attribute name in SQLAlchemy (it refers to the table's MetaData object), accessing `ind.metadata` returned the wrong type.

**Solution:** Changed `ind.metadata` to `ind.extra_data` in `backend/app/api/v1/threat_intel.py` (3 occurrences in `list_indicators`, `check_indicator` response building).

**Lesson:** Avoid naming model columns `metadata` as it conflicts with SQLAlchemy's built-in attribute. Use names like `extra_data`, `meta`, or `additional_data` instead.

**File:** `backend/app/api/v1/threat_intel.py`

---

### FastAPI Route Ordering - Dynamic vs Static Paths

**Problem:** `/api/v1/devices/quarantined` returning 422 Unprocessable Entity

**Cause:** FastAPI matches routes in definition order. The `/{device_id}` route was defined before `/quarantined`, so requests to `/quarantined` matched `/{device_id}` first. Since `device_id` is typed as `UUID`, FastAPI tried to parse "quarantined" as a UUID and failed validation.

**Solution:** Reorder routes so static paths come before dynamic path parameters:

```python
# CORRECT ORDER:
@router.get("")                    # /devices
@router.get("/quarantined")        # /devices/quarantined (static)
@router.get("/export/csv")         # /devices/export/csv (static)
@router.get("/tags/all")           # /devices/tags/all (static)
@router.post("/bulk-tag")          # /devices/bulk-tag (static)
@router.get("/{device_id}")        # /devices/{uuid} (dynamic - LAST)
@router.patch("/{device_id}")
@router.put("/{device_id}/tags")
```

**Lesson:** In FastAPI, always define static routes before routes with path parameters. This applies to any route file with both patterns.

**File:** `backend/app/api/v1/devices.py`

---

### TestRuleModal 422 Validation Error

**Problem:** Clicking "Test Rule" button returned 422 Unprocessable Entity error

**Cause:** The backend's Pydantic validator requires each condition to have non-empty `field`, valid `operator`, and `value` fields. Rules loaded from the database could have:
- Empty string values for `field` or `operator`
- Undefined `value` properties
- Whitespace-only strings

**Solution:** Added validation and sanitization in `TestRuleModal.tsx`:
1. Filter out conditions with empty/whitespace `field` or `operator`
2. Trim whitespace from all string values
3. Use nullish coalescing (`??`) to ensure `value` is never undefined
4. Show user-friendly error if no valid conditions exist

```typescript
const validConditions = rawConditions.filter(
  (c) => c.field && c.field.trim() !== '' && c.operator && c.operator.trim() !== ''
);

const sanitizedConditions = validConditions.map((c) => ({
  field: c.field.trim(),
  operator: c.operator.trim(),
  value: c.value ?? '',
}));
```

**File:** `frontend/src/components/TestRuleModal.tsx`

---

### Legacy Conditions Format Detection Pattern

**Problem:** Rules created with older code or seeded data use a flat `conditions` array, but the UI expects `condition_groups` with logical operators.

**Legacy Format:**
```json
{
  "conditions": [
    { "field": "event_type", "operator": "eq", "value": "dns" },
    { "field": "severity", "operator": "gte", "value": "medium" }
  ]
}
```

**New Format:**
```json
{
  "condition_groups": [
    {
      "logical_operator": "AND",
      "conditions": [
        { "field": "event_type", "operator": "eq", "value": "dns" },
        { "field": "severity", "operator": "gte", "value": "medium" }
      ]
    }
  ]
}
```

**Detection Pattern:**
```typescript
const hasLegacyConditions =
  rule.conditions &&
  Array.isArray(rule.conditions) &&
  rule.conditions.length > 0 &&
  (!rule.condition_groups || rule.condition_groups.length === 0);
```

**Conversion Pattern:**
```typescript
if (hasLegacyConditions) {
  const converted = [{
    logical_operator: 'AND' as const,
    conditions: rule.conditions.map(c => ({
      field: c.field || '',
      operator: c.operator || 'eq',
      value: c.value ?? ''
    }))
  }];
  // Use converted format
}
```

**Files affected:** `TestRuleModal.tsx`, `EditRuleModal.tsx`

---

### Optimistic UI Updates Pattern

**Problem:** Enable/disable toggles feel sluggish when waiting for API response.

**Solution:** Update UI immediately, then rollback on error.

```typescript
const handleToggle = async (source: Source) => {
  // Store previous state for rollback
  const previousEnabled = source.enabled;

  // Optimistically update UI
  queryClient.setQueryData(['sources'], (old: Source[] | undefined) =>
    old?.map(s => s.id === source.id ? { ...s, enabled: !s.enabled } : s)
  );

  try {
    await toggleMutation.mutateAsync({ id: source.id, enabled: !previousEnabled });
  } catch (error) {
    // Rollback on error
    queryClient.setQueryData(['sources'], (old: Source[] | undefined) =>
      old?.map(s => s.id === source.id ? { ...s, enabled: previousEnabled } : s)
    );
    toast.error('Failed to update source');
  }
};
```

**File:** `frontend/src/pages/SourcesPage.tsx`

---

## Authentik OIDC Integration Notes (January 2026)

### PKCE Flow Implementation

The OIDC integration uses PKCE (Proof Key for Code Exchange) for security:

1. **Frontend generates code_verifier** - Random 64-byte URL-safe string stored in sessionStorage
2. **Backend generates code_challenge** - SHA256 hash of verifier, base64url encoded
3. **Redirect to Authentik** - Include code_challenge in authorization URL
4. **Callback validation** - Frontend sends code_verifier back to backend
5. **Token exchange** - Backend sends verifier to Authentik, which validates against original challenge

**Key files:**
- `backend/app/services/oidc_service.py` - generate_pkce(), exchange_code()
- `frontend/src/pages/LoginPage.tsx` - handleSSOLogin() generates verifier
- `frontend/src/pages/OIDCCallbackPage.tsx` - Retrieves verifier from sessionStorage

### State Parameter for CSRF Protection

State is stored in Redis with 5-minute TTL:
```python
await cache_manager.set(f"oidc_state:{state}", code_verifier, ttl=300)
```

The callback validates state by checking Redis before processing the code exchange.

### Group to Role Mapping

Group mappings are configured via JSON in environment:
```
AUTHENTIK_GROUP_MAPPINGS={"netguardian-admins": "admin", "netguardian-operators": "operator"}
```

Role priority order: admin > operator > viewer (first matching role wins)

### External User Tracking

Users authenticated via Authentik are tracked with:
- `external_id` - Authentik's `sub` claim (unique identifier)
- `external_provider` - Set to "authentik"
- `is_external` - Boolean flag for external auth

External users can still have local passwords disabled or set for emergency access.

### Email-Based User Linking

When a user logs in via Authentik SSO, the callback endpoint uses this lookup order:

1. **Look up by `external_id`** - Find existing SSO-linked user
2. **Look up by email** - Find pre-created local user to link
3. **Create new user** - Only if `AUTHENTIK_AUTO_CREATE_USERS=true`

This enables two workflows:

**Auto-create mode** (`AUTHENTIK_AUTO_CREATE_USERS=true`):
- Any Authentik user can access NetGuardian
- User account created automatically on first SSO login
- Role assigned from Authentik groups or default role

**Pre-create mode** (`AUTHENTIK_AUTO_CREATE_USERS=false`):
- Admin creates users in NetGuardian with specific roles
- User email must match their Authentik email exactly
- On first SSO login, accounts are linked by email match
- Unregistered users are rejected with 403 error

**Implementation:** `backend/app/api/v1/auth.py:583-625` in `oidc_callback()` endpoint

### Authentik Event Parser

The parser handles Authentik's `/api/v3/events/` API format:
- Paginated responses: `{"results": [...], "pagination": {...}}`
- Direct list of events: `[{...}, {...}]`

Action to severity mapping:
- INFO: login, logout, authorize_application, model_created/updated/deleted
- WARNING: login_failed, impersonation_started/ended, policy_exception
- ERROR: suspicious_request, configuration_error, secret_view

Security events are flagged with `is_security_event: true` in parsed_fields.

---

### Dark Theme Modal Styling Checklist

When fixing dark theme for modals, ensure these elements have proper styling:

1. **Container:** `dark:bg-zinc-800` or `dark:bg-zinc-900`
2. **Header text:** `dark:text-white`
3. **Labels:** `dark:text-gray-300`
4. **Input fields:** `dark:bg-zinc-700 dark:border-zinc-600 dark:text-white`
5. **Select/dropdowns:** Same as inputs, plus `dark:text-white` for options
6. **Checkboxes:** `dark:bg-zinc-700 dark:border-zinc-500`
7. **Primary buttons:** Usually fine, check hover states
8. **Secondary buttons:** `dark:bg-zinc-700 dark:hover:bg-zinc-600 dark:text-gray-300`
9. **Close/X button:** `dark:text-gray-400 dark:hover:text-gray-200`
10. **Error messages:** `dark:text-red-400`
11. **Placeholder text:** `dark:placeholder-gray-500`

**Common mistake:** Forgetting `dark:text-white` on select options, making them invisible on dark backgrounds.

---

## Docker/Portainer Command Parsing Issues (January 2026)

### Problem: "python -m app.worker: not found"

**Error:** `sh: 1: python -m app.worker: not found`

**Cause:** Portainer (and some Docker orchestration tools) mishandle command overrides. When you enter `python -m app.worker` in Portainer's command field, it wraps the command incorrectly, causing the shell to interpret the entire string as a single command name rather than `python` with arguments.

**Why this happens:**
1. Portainer may pass the command through `sh -c "command"`
2. The quoting/escaping gets mangled, resulting in the whole string being treated as one word
3. This is a known issue with various Docker UIs and orchestration tools

### Solution: NETGUARDIAN_MODE Environment Variable

Instead of relying on command overrides, use an entrypoint script that reads a mode from environment variables:

**docker-entrypoint.sh:**
```bash
#!/bin/bash
MODE="${NETGUARDIAN_MODE:-api}"
case "$MODE" in
    api) exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2 ;;
    worker|collector) exec python -m app.worker ;;
    migrations) exec alembic upgrade head ;;
esac
```

**Dockerfile changes:**
```dockerfile
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD []
```

**docker-compose usage:**
```yaml
collector:
  image: apetalous/netguardian-backend:latest
  environment:
    - NETGUARDIAN_MODE=worker  # Instead of command override
```

**In Portainer:** Set environment variable `NETGUARDIAN_MODE=worker` instead of modifying the command field.

**Valid modes:**
- `api` (default) - Run the FastAPI backend
- `worker` or `collector` - Run the collector worker
- `migrations` - Run database migrations

### Related Issue: async_session_factory Import Error

**Error:** `ImportError: cannot import name 'async_session_factory' from 'app.db.session'`

**Cause:** Code mismatch between `collector_service.py` (importing `async_session_factory`) and `session.py` (exporting `AsyncSessionLocal`).

**Solution:** Updated `collector_service.py` to import `AsyncSessionLocal` instead of `async_session_factory`.

---

### Event Processing Performance Pattern
When processing high-volume log events:
1. **Batch inserts** - Collect events into batches (100-500 events) before DB commit
2. **Concurrent batches** - Use `asyncio.create_task()` with semaphore to limit parallelism
3. **Deferred heavy processing** - Queue semantic analysis for background worker
4. **Cache frequently accessed data** - Cache device lookups with TTL (5 min)

Key constants in `backend/app/services/collector_service.py`:
- `BATCH_SIZE = 100` - Events per batch
- `BATCH_TIMEOUT = 2.0` - Seconds before flushing incomplete batch
- `MAX_CONCURRENT_BATCHES = 3` - Concurrent batch limit
- `DEVICE_CACHE_TTL = 300` - Device cache TTL in seconds
- `SEMANTIC_QUEUE_SIZE = 10000` - Max queued events for analysis

### Podman Registry Error on Linux
Error: `short-name "image" did not resolve to an alias and no unqualified-search registries are defined`

Fix:
```bash
echo 'unqualified-search-registries = ["docker.io"]' | sudo tee /etc/containers/registries.conf.d/docker.conf
```

---

## File Watch Collector - read_from_end Option (January 2026)

**Problem:** Nginx error logs (or other file_watch sources) show 0 events even though the log file has entries.

**Cause:** The `FileWatchCollector` defaults to `read_from_end=True` (`file_collector.py:93`). This means:
- On startup, the collector seeks to the END of the file
- Only NEW lines appended after the collector starts are processed
- Existing entries in the file are NOT read

**Solution:** Added `read_from_end` option to the frontend source configuration:
- `AddSourceModal.tsx` and `EditSourceModal.tsx` now have a "Read from end of file" checkbox
- Default is `true` (only new entries) - good for ongoing monitoring
- Set to `false` to import historical data from existing log files

**When to disable read_from_end:**
- Importing historical logs that already exist in the file
- Testing parser configuration with existing log data
- One-time data migration scenarios

**Note:** After importing historical data, consider re-enabling `read_from_end` to avoid re-processing the same entries on collector restart.

---

## File Watch Collector - Directory Mode (January 2026)

**Feature:** The File Watcher Collector now supports watching an entire directory with glob pattern filtering.

**Use cases:**
- Rotated log files (e.g., `app.log`, `app.log.1`, `app.log.2`)
- Date-based log files (e.g., `access-2026-01-01.log`, `access-2026-01-02.log`)
- Multiple service logs in a shared directory

**Configuration:**
```json
{
  "path": "/var/log/myapp/",       // Directory path (not file)
  "file_pattern": "*.log",         // Glob pattern for filtering
  "follow": true,
  "read_from_end": true
}
```

**How it works:**
1. When `path` is a directory, collector enters directory mode
2. On start, scans for all files matching `file_pattern`
3. Opens each matching file with independent position tracking
4. Watches for `on_created` events to pick up new files
5. Watches for `on_deleted` events to clean up handles
6. Reads from all modified files on each poll cycle

**Glob pattern examples:**
- `*.log` - All .log files
- `app-*.log` - All app-*.log files (e.g., app-error.log, app-access.log)
- `access.log*` - All access.log variants (e.g., access.log, access.log.1)
- `*` - All files (default)

**Frontend UI:**
- "Watch Directory" checkbox enables directory mode
- "File Pattern" input appears when directory mode is enabled
- Path label changes between "Log File Path" and "Log Directory Path"

**Connection test shows:**
- For directories: "Directory is readable: /path (N files match 'pattern')"
- For files: "File is readable: /path" (unchanged behavior)
