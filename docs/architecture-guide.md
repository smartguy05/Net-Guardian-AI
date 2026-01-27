# NetGuardian AI - Architecture Learning Guide

A comprehensive step-by-step guide to understanding the NetGuardian AI codebase.

---

## Table of Contents

1. [Overview: The Big Picture](#1-overview-the-big-picture)
2. [Core Concepts](#2-core-concepts)
3. [Data Collection Pipeline](#3-data-collection-pipeline)
4. [Event Storage & Database](#4-event-storage--database)
5. [Anomaly Detection System](#5-anomaly-detection-system)
6. [LLM Integration](#6-llm-integration)
7. [Security & Authentication](#7-security--authentication)
8. [Frontend Architecture](#8-frontend-architecture)
9. [Real-time Updates](#9-real-time-updates)
10. [Automated Response](#10-automated-response)
11. [Complete Data Flow Walkthrough](#11-complete-data-flow-walkthrough)

---

## 1. Overview: The Big Picture

### What NetGuardian AI Does

NetGuardian AI is a home network security monitoring system that:
- **Collects** logs from multiple sources (DNS servers, firewalls, routers, endpoints)
- **Normalizes** different log formats into a unified structure
- **Learns** normal behavior patterns for each device
- **Detects** anomalies when behavior deviates from baselines
- **Analyzes** suspicious activity using AI (Claude or Ollama)
- **Responds** automatically with playbooks (quarantine, notifications, webhooks)

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                             │
│  AdGuard Home │ Syslog │ NetFlow │ sFlow │ Endpoint Agents      │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      COLLECTION LAYER                            │
│         Collectors pull/receive data from sources                │
│         Parsers normalize into unified format                    │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       STORAGE LAYER                              │
│    TimescaleDB (events) │ Redis (cache/queue) │ PostgreSQL      │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ANALYSIS LAYER                              │
│   Baseline Calculation │ Anomaly Detection │ LLM Analysis       │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      RESPONSE LAYER                              │
│        Alerts │ Playbooks │ Quarantine │ Notifications          │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       PRESENTATION                               │
│              React Frontend │ REST API │ WebSocket               │
└─────────────────────────────────────────────────────────────────┘
```

### Key Technologies

| Layer | Technology | Purpose |
|-------|------------|---------|
| Backend | FastAPI | Async REST API framework |
| Database | TimescaleDB | Time-series optimized PostgreSQL |
| Cache/Queue | Redis | Event bus, caching, rate limiting |
| AI | Claude/Ollama | Semantic log analysis |
| Frontend | React + TypeScript | User interface |
| State | Zustand + React Query | Client state management |
| Styling | Tailwind CSS | Utility-first CSS |

---

## 2. Core Concepts

### 2.1 The Registry Pattern

NetGuardian uses a **decorator-based registry pattern** for extensibility. This allows adding new collectors or parsers without modifying core code.

**How it works:**

```python
# In registry.py - the registry stores mappings
class CollectorRegistry:
    _collectors: Dict[SourceType, Type[BaseCollector]] = {}

    @classmethod
    def register(cls, source_type, collector_class):
        cls._collectors[source_type] = collector_class

# Decorator makes registration automatic
def register_collector(source_type: SourceType):
    def decorator(cls):
        CollectorRegistry.register(source_type, cls)
        return cls
    return decorator
```

**Usage - just add the decorator:**

```python
@register_collector(SourceType.API_PULL)
class ApiPullCollector(BaseCollector):
    # This class is now automatically registered!
    pass
```

**Why this matters:** To add a new log source, you just:
1. Create a new parser class with `@register_parser("myparser")`
2. Create a new collector if needed with `@register_collector(SourceType.MY_TYPE)`
3. The system automatically discovers and uses them

### 2.2 The ParseResult: Universal Event Format

All parsers produce the same output format, regardless of input:

```python
@dataclass
class ParseResult:
    timestamp: datetime          # When it happened
    event_type: EventType        # DNS, FIREWALL, AUTH, etc.
    severity: EventSeverity      # DEBUG, INFO, WARNING, ERROR, CRITICAL
    raw_message: str             # Original log line
    client_ip: Optional[str]     # Source IP
    target_ip: Optional[str]     # Destination IP
    domain: Optional[str]        # Domain name (for DNS)
    port: Optional[int]          # Port number
    protocol: Optional[str]      # TCP, UDP, DNS, etc.
    action: Optional[str]        # allowed, blocked, etc.
    parsed_fields: Dict          # Extra fields as JSON
```

**Why this matters:** Downstream code (anomaly detection, storage, UI) doesn't need to know if the event came from AdGuard, a firewall, or NetFlow - it's all the same structure.

### 2.3 Async Everything

The backend is fully asynchronous using Python's `asyncio`:

```python
# Database sessions are async
async def get_device(session: AsyncSession, device_id: UUID) -> Device:
    result = await session.execute(
        select(Device).where(Device.id == device_id)
    )
    return result.scalar_one_or_none()

# API endpoints are async
@router.get("/devices/{device_id}")
async def get_device_endpoint(
    device_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    return await get_device(session, device_id)
```

**Why this matters:** Async allows handling thousands of concurrent connections efficiently. While waiting for database queries or API calls, the server can process other requests.

---

## 3. Data Collection Pipeline

### 3.1 Collector Types

Three collector types handle different data acquisition patterns:

| Collector | Use Case | How It Works |
|-----------|----------|--------------|
| `ApiPullCollector` | REST APIs (AdGuard, Loki) | Polls endpoint every N seconds |
| `FileCollector` | Log files | Watches file for new lines (tail -f) |
| `UdpListenerCollector` | Network protocols (syslog, NetFlow) | Listens on UDP port |

### 3.2 ApiPullCollector Deep Dive

This is the most complex collector. Let's trace through it:

**Step 1: Configuration**

When you create a log source in the UI, it stores config like:
```json
{
  "url": "http://192.168.1.1",
  "endpoint": "/control/querylog",
  "auth_type": "basic",
  "username": "admin",
  "password": "secret",
  "poll_interval_seconds": 30
}
```

**Step 2: Initialization**

```python
# api_pull_collector.py lines 55-76
def __init__(self, source: LogSource, parser: BaseParser):
    super().__init__(source, parser)

    # Error handling setup
    retry_config = RetryConfig(max_retries=3)
    self._circuit_breaker = CircuitBreaker(failure_threshold=5)
    self._retry_handler = RetryHandler(retry_config, self._circuit_breaker)
```

**Step 3: Polling Loop**

```python
# Runs continuously in background
async def _poll_loop(self):
    interval = self.config.get("poll_interval_seconds", 30)

    while self._running:
        results = await self._poll_once()  # Fetch and parse
        for result in results:
            await self._event_queue.put(result)  # Queue for consumers
        await asyncio.sleep(interval)
```

**Step 4: Making Requests with Retry**

```python
async def _poll_once(self):
    # Use retry handler - automatically retries on failure
    response_data = await self._retry_handler.execute(
        self._make_request,
        self.source_id,
        "api_poll",
    )

    # Parse the response using the configured parser
    results = self.parser.parse(response_data)
    return results
```

### 3.3 Error Handling: Retry + Circuit Breaker

**Retry Handler** - Tries again with exponential backoff:
```
Attempt 1: Immediate
Attempt 2: Wait 1s
Attempt 3: Wait 2s
Attempt 4: Wait 4s
...up to max_delay
```

**Circuit Breaker** - Stops trying when service is clearly down:
```
CLOSED (normal) ──[5 failures]──> OPEN (reject all)
                                      │
                              [30s timeout]
                                      │
                                      ▼
                                 HALF_OPEN (test)
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
              [success × 3]                        [failure]
                    │                                   │
                    ▼                                   ▼
                 CLOSED                              OPEN
```

**Why this matters:** If AdGuard Home goes offline, the system doesn't spam it with requests. It waits, tests occasionally, and recovers automatically.

### 3.4 Parser Example: AdGuard

Parsers transform raw data into `ParseResult`:

```python
@register_parser("adguard")
class AdGuardParser(BaseParser):

    def parse(self, raw_data: Any) -> List[ParseResult]:
        results = []

        # Handle API response format
        entries = raw_data.get("data", [])

        for entry in entries:
            # Extract fields from AdGuard's JSON structure
            timestamp = self._parse_timestamp(entry.get("time"))
            domain = entry.get("question", {}).get("name", "").rstrip(".")
            client_ip = entry.get("client", "")

            # Determine if blocked
            action = self._determine_action(entry)  # "allowed" or "blocked"
            severity = self._determine_severity(entry)  # WARNING if blocked

            result = ParseResult(
                timestamp=timestamp,
                event_type=EventType.DNS,
                severity=severity,
                raw_message=f"{client_ip} -> {domain}",
                client_ip=client_ip,
                domain=domain,
                action=action,
                # ... more fields
            )
            results.append(result)

        return results
```

---

## 4. Event Storage & Database

### 4.1 TimescaleDB Hypertables

Events are stored in a **hypertable** - a PostgreSQL table optimized for time-series data:

```python
class RawEvent(Base):
    __tablename__ = "raw_events"

    # Composite primary key includes timestamp
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,  # Part of composite PK for hypertable
    )

    # Core fields
    event_type: Mapped[EventType]  # DNS, FIREWALL, AUTH, etc.
    severity: Mapped[EventSeverity]
    client_ip: Mapped[Optional[str]]
    domain: Mapped[Optional[str]]
    action: Mapped[Optional[str]]

    # Flexible JSON for extra data
    parsed_fields: Mapped[Dict] = mapped_column(JSONB)

    # Link to device
    device_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("devices.id")
    )
```

**How hypertables work:**
- Data is automatically partitioned into **chunks** by time (7-day chunks)
- Old chunks can be dropped efficiently for retention
- Queries on time ranges are fast (only scans relevant chunks)
- Compression can be applied to old chunks

### 4.2 Key Database Models

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Device    │────<│  RawEvent   │     │    Alert    │
│             │     │ (hypertable)│     │             │
│ - hostname  │     │ - timestamp │     │ - severity  │
│ - ip_address│     │ - event_type│     │ - status    │
│ - mac_addr  │     │ - client_ip │     │ - device_id │
│ - status    │     │ - domain    │     │ - rule_id   │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       │            ┌──────┴──────┐            │
       │            ▼             ▼            │
       │    ┌─────────────┐ ┌─────────────┐   │
       └───>│DeviceBaseline│ │AnomalyDetect│<──┘
            │             │ │             │
            │ - metrics   │ │ - score     │
            │ - status    │ │ - type      │
            └─────────────┘ └─────────────┘
```

### 4.3 SQLAlchemy 2.0 Patterns

**Enum handling for PostgreSQL:**
```python
# Must use values_callable for PostgreSQL enums
role: Mapped[UserRole] = mapped_column(
    SQLEnum(
        UserRole,
        name="userrole",
        values_callable=lambda x: [e.value for e in x]
    ),
)
```

**Async queries:**
```python
async def get_events_for_device(
    session: AsyncSession,
    device_id: UUID,
    hours: int = 24
) -> list[RawEvent]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await session.execute(
        select(RawEvent)
        .where(RawEvent.device_id == device_id)
        .where(RawEvent.timestamp >= cutoff)
        .order_by(RawEvent.timestamp.desc())
    )
    return result.scalars().all()
```

---

## 5. Anomaly Detection System

### 5.1 Two-Phase Detection

Anomaly detection happens in two phases:

**Phase 1: Baseline Learning**
- Analyze N days of historical events per device
- Calculate statistical profiles (means, standard deviations, patterns)
- Status: `learning` → `partial` → `ready`

**Phase 2: Anomaly Detection**
- Compare current behavior against baseline
- Flag deviations using z-scores and pattern matching
- Create alerts for high-severity anomalies

### 5.2 Baseline Calculation

```python
class BaselineCalculator:
    async def calculate_dns_baseline(
        self,
        device_id: UUID,
        window_days: int = 7,
        min_samples: int = 100,
    ) -> DeviceBaseline:
        # Fetch historical events
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        events = await self._get_events(device_id, cutoff)

        # Calculate metrics
        metrics = self._calculate_dns_metrics(events)

        return DeviceBaseline(
            device_id=device_id,
            baseline_type=BaselineType.DNS,
            metrics=metrics,  # Stored as JSONB
            sample_count=len(events),
            status=self._determine_status(len(events), min_samples),
        )
```

**DNS Baseline Metrics:**
```python
def _calculate_dns_metrics(self, events):
    return {
        "unique_domains": list(unique_domains),      # Known domains
        "domain_frequencies": dict(domain_counter),  # How often each
        "hourly_distribution": hourly_counts,        # Activity by hour
        "volume_mean": statistics.mean(daily_volumes),
        "volume_std": statistics.stdev(daily_volumes),
        "blocked_ratio": blocked / total,            # Normal block rate
    }
```

### 5.3 Anomaly Detection Logic

```python
class AnomalyDetector:
    async def detect_anomalies(self, device_id: UUID) -> List[AnomalyDetection]:
        anomalies = []

        # Get device's baseline
        baseline = await self._get_baseline(device_id, BaselineType.DNS)

        # Get recent events (last hour)
        recent_events = await self._get_recent_events(device_id, hours=1)

        # Check for different anomaly types
        anomalies.extend(self._check_new_domains(recent_events, baseline))
        anomalies.extend(self._check_volume_spike(recent_events, baseline))
        anomalies.extend(self._check_time_anomaly(recent_events, baseline))
        anomalies.extend(self._check_blocked_spike(recent_events, baseline))

        return anomalies
```

### 5.4 Anomaly Types

| Type | Detection Logic | Example |
|------|-----------------|---------|
| `NEW_DOMAIN` | Domain not in baseline's known domains | Device suddenly queries `malware-c2.evil` |
| `VOLUME_SPIKE` | Z-score > 2.0 above normal volume | 10x normal DNS queries |
| `TIME_ANOMALY` | Activity 3x expected for this hour | IoT device active at 3 AM |
| `BLOCKED_SPIKE` | 2x normal blocked query ratio | Many blocked malware domains |
| `NEW_CONNECTION` | Connection to unknown IP/port | Outbound connection to unusual port |

### 5.5 Z-Score Calculation

Z-score measures how many standard deviations a value is from the mean:

```python
def _check_volume_spike(self, events, baseline):
    current_volume = len(events)
    expected_mean = baseline.metrics["volume_mean"]
    expected_std = baseline.metrics["volume_std"]

    # Z-score formula: (observed - expected) / standard_deviation
    z_score = (current_volume - expected_mean) / expected_std

    if z_score >= 2.0:  # Threshold
        return AnomalyDetection(
            anomaly_type=AnomalyType.VOLUME_SPIKE,
            score=z_score,
            severity=self._score_to_severity(z_score),
            description=f"Volume {z_score:.1f} std devs above normal"
        )
```

### 5.6 Severity Calculation

```python
# Score thresholds for severity
def calculate_severity(score: float, anomaly_type: AnomalyType) -> AlertSeverity:
    # High-risk types get elevated severity
    if anomaly_type in {AnomalyType.NEW_CONNECTION, AnomalyType.BLOCKED_SPIKE}:
        if score >= 4.0: return AlertSeverity.CRITICAL
        if score >= 3.0: return AlertSeverity.HIGH
        if score >= 2.0: return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    # Standard severity
    if score >= 5.0: return AlertSeverity.CRITICAL
    if score >= 4.0: return AlertSeverity.HIGH
    if score >= 3.0: return AlertSeverity.MEDIUM
    return AlertSeverity.LOW
```

---

## 6. LLM Integration

### 6.1 Provider Architecture

The LLM system uses a **factory pattern** for provider abstraction:

```
┌─────────────────────┐
│  BaseLLMProvider    │  ← Abstract interface
│  - analyze_logs()   │
│  - is_available()   │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │           │
    ▼           ▼
┌────────┐  ┌────────┐
│ Claude │  │ Ollama │
│Provider│  │Provider│
└────────┘  └────────┘
```

**Factory creates the right provider:**
```python
def get_llm_provider(provider_name: str = None) -> BaseLLMProvider:
    provider_name = provider_name or settings.semantic_default_llm_provider

    if provider_name == "claude":
        return ClaudeLLMProvider()
    elif provider_name == "ollama":
        return OllamaLLMProvider()
    else:
        raise ValueError(f"Unknown provider: {provider_name}")
```

### 6.2 Semantic Analysis Flow

```python
class SemanticAnalysisService:
    async def analyze_irregular_logs(self, logs: List[IrregularLog]):
        # 1. Format logs for LLM
        formatted_logs = [
            {
                "index": i,
                "message": log.raw_message,
                "source": log.source_name,
                "timestamp": log.timestamp.isoformat(),
                "reason": log.irregularity_reason,
            }
            for i, log in enumerate(logs)
        ]

        # 2. Get LLM provider
        provider = get_llm_provider()

        # 3. Analyze
        result = await provider.analyze_logs(formatted_logs)

        # 4. Process results
        for concern in result.concerns:
            await self._create_alert(logs[concern.log_index], concern)

        for rule in result.suggested_rules:
            await self._create_suggested_rule(rule)
```

### 6.3 The System Prompt

The LLM receives a detailed system prompt that instructs it on:

```python
SEMANTIC_ANALYSIS_SYSTEM_PROMPT = """You are a security analyst reviewing
system logs that have been flagged as "irregular"...

For each batch of logs, analyze them for potential security concerns including:
- Unauthorized access or authentication anomalies
- Privilege escalation attempts
- Suspicious process or service behavior
- Malware indicators or command-and-control patterns
- Data exfiltration attempts
...

Respond with a JSON structure:
{
  "summary": "Brief overview of findings",
  "concerns": [
    {
      "log_index": 0,
      "severity": 0.8,
      "concern": "Description of concern",
      "recommendation": "Suggested action"
    }
  ],
  "benign_explanations": [...],
  "suggested_rules": [...]
}"""
```

### 6.4 Claude Provider Implementation

```python
class ClaudeLLMProvider(BaseLLMProvider):
    async def analyze_logs(self, logs, context=None):
        prompt = self._build_analysis_prompt(logs, context)

        # Call Claude API with prompt caching
        response = await self.client.messages.create(
            model=self._model,
            max_tokens=4096,
            temperature=0.3,  # Low temperature for consistent analysis
            system=[{
                "type": "text",
                "text": SEMANTIC_ANALYSIS_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},  # Cache system prompt
            }],
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse JSON response
        result_dict = self._parse_json_response(response.content[0].text)
        return LLMAnalysisResult.from_dict(result_dict)
```

### 6.5 Rule Suggestions

When the LLM identifies a pattern, it suggests detection rules:

```python
@dataclass
class SuggestedRuleData:
    name: str           # "Detect PowerShell Download Cradle"
    description: str    # What it detects
    reason: str         # Why suggested based on this log
    benefit: str        # How it improves security
    rule_type: str      # "pattern_match", "threshold", "sequence"
    rule_config: dict   # The actual rule configuration
```

Example suggested rule:
```json
{
  "name": "Detect Base64 Encoded Commands",
  "description": "Detects PowerShell commands with base64 encoding",
  "rule_type": "pattern_match",
  "rule_config": {
    "pattern": "powershell.*-enc.*[A-Za-z0-9+/=]{50,}",
    "fields": ["raw_message"],
    "severity": "high"
  }
}
```

---

## 7. Security & Authentication

### 7.1 Authentication Flow

```
┌────────┐     POST /auth/login      ┌─────────┐
│ Client │ ──────────────────────────>│ Backend │
│        │   {username, password}    │         │
│        │                           │         │
│        │     {access_token,        │         │
│        │ <────refresh_token,       │         │
│        │      requires_2fa?}       │         │
│        │                           │         │
│        │ ─── If 2FA required ────> │         │
│        │   POST /auth/verify-2fa   │         │
│        │   {temp_token, totp_code} │         │
│        │                           │         │
│        │     {access_token,        │         │
│        │ <────refresh_token}       │         │
└────────┘                           └─────────┘
```

### 7.2 JWT Tokens

```python
def create_access_token(
    subject: str,      # User ID
    role: UserRole,    # admin, operator, viewer
    expires_delta: timedelta = None,
) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))

    payload = {
        "sub": subject,
        "role": role.value,
        "exp": expire,
        "type": "access",
    }

    return jwt.encode(payload, settings.secret_key, algorithm="HS256")
```

**Token types:**
- **Access token**: Short-lived (30 min), used for API requests
- **Refresh token**: Long-lived (7 days), used to get new access tokens

### 7.3 Role-Based Access Control (RBAC)

```python
# Role hierarchy
ROLE_HIERARCHY = {
    UserRole.ADMIN: {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    UserRole.OPERATOR: {UserRole.OPERATOR, UserRole.VIEWER},
    UserRole.VIEWER: {UserRole.VIEWER},
}

# Permissions by role
PERMISSIONS = {
    # Everyone can view
    "view:dashboard": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    "view:devices": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},

    # Operators can act
    "action:quarantine_device": {UserRole.ADMIN, UserRole.OPERATOR},
    "action:acknowledge_alert": {UserRole.ADMIN, UserRole.OPERATOR},

    # Only admins can manage
    "manage:users": {UserRole.ADMIN},
    "manage:rules": {UserRole.ADMIN},
}
```

**Permission check:**
```python
def require_permission(permission: str):
    def decorator(func):
        async def wrapper(current_user: User = Depends(get_current_user)):
            allowed_roles = PERMISSIONS.get(permission, set())
            if current_user.role not in allowed_roles:
                raise HTTPException(403, "Permission denied")
            return await func(current_user=current_user)
        return wrapper
    return decorator

@router.delete("/users/{user_id}")
@require_permission("manage:users")
async def delete_user(user_id: UUID, current_user: User):
    # Only admins reach here
    ...
```

### 7.4 Two-Factor Authentication (2FA)

```python
# Generate TOTP secret for user
def setup_2fa(user: User) -> str:
    secret = pyotp.random_base32()
    user.totp_secret = secret

    # Generate QR code URI for authenticator apps
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(user.email, issuer_name="NetGuardian")
    return uri

# Verify TOTP code
def verify_2fa(user: User, code: str) -> bool:
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(code, valid_window=1)  # Allow 30s clock skew
```

### 7.5 Rate Limiting

**Token Bucket Algorithm:**
```python
class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity      # Max tokens
        self.refill_rate = refill_rate  # Tokens per second
        self.tokens = capacity
        self.last_refill = time.time()

    async def consume(self, tokens: int = 1) -> bool:
        # Refill based on time elapsed
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        # Try to consume
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False  # Rate limited
```

**Default limits by endpoint type:**
```python
DEFAULT_LIMITS = {
    "default": 60 requests/minute,
    "auth": 10 requests/minute,      # Prevent brute force
    "chat": 20 requests/minute,      # LLM is expensive
    "export": 5 requests/minute,     # Heavy operations
}
```

---

## 8. Frontend Architecture

### 8.1 State Management with Zustand

Zustand provides simple, hook-based state management:

```typescript
// stores/auth.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      isAuthenticated: false,

      login: (user, accessToken) => set({
        user,
        accessToken,
        isAuthenticated: true,
      }),

      logout: () => set({
        user: null,
        accessToken: null,
        isAuthenticated: false,
      }),
    }),
    {
      name: 'netguardian-auth',  // localStorage key
    }
  )
);
```

**Usage in components:**
```typescript
function Navbar() {
  const { user, logout } = useAuthStore();

  return (
    <nav>
      <span>Welcome, {user?.username}</span>
      <button onClick={logout}>Logout</button>
    </nav>
  );
}
```

### 8.2 API Client with Axios

```typescript
// api/client.ts
const apiClient = axios.create({
  baseURL: '/api/v1',
});

// Add auth token to every request
apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-refresh expired tokens
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Try to refresh token
      const refreshToken = useAuthStore.getState().refreshToken;
      if (refreshToken) {
        const response = await axios.post('/api/v1/auth/refresh', {
          refresh_token: refreshToken,
        });
        // Update tokens and retry request
        useAuthStore.getState().setTokens(response.data.access_token);
        return apiClient(error.config);
      }
      // Refresh failed, logout
      useAuthStore.getState().logout();
    }
    return Promise.reject(error);
  }
);
```

### 8.3 React Query for Server State

```typescript
// api/hooks.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

// Fetch devices
export function useDevices() {
  return useQuery({
    queryKey: ['devices'],
    queryFn: async () => {
      const { data } = await apiClient.get('/devices');
      return data;
    },
  });
}

// Quarantine a device
export function useQuarantineDevice() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (deviceId: string) => {
      await apiClient.post(`/devices/${deviceId}/quarantine`);
    },
    onSuccess: () => {
      // Invalidate cache to refetch devices
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });
}
```

**Usage in components:**
```typescript
function DeviceList() {
  const { data: devices, isLoading, error } = useDevices();
  const quarantine = useQuarantineDevice();

  if (isLoading) return <Spinner />;
  if (error) return <Error message={error.message} />;

  return (
    <ul>
      {devices.map(device => (
        <li key={device.id}>
          {device.hostname}
          <button onClick={() => quarantine.mutate(device.id)}>
            Quarantine
          </button>
        </li>
      ))}
    </ul>
  );
}
```

### 8.4 Page Structure

```
frontend/src/
├── pages/
│   ├── DashboardPage.tsx      # Main dashboard with stats
│   ├── DevicesPage.tsx        # Device inventory
│   ├── EventsPage.tsx         # Event log viewer
│   ├── AlertsPage.tsx         # Alert management
│   ├── RulesPage.tsx          # Detection rules
│   ├── SemanticReviewPage.tsx # LLM analysis results
│   └── SettingsPage.tsx       # User settings
├── components/
│   ├── modals/                # Modal dialogs
│   ├── tables/                # Data tables
│   └── charts/                # Visualization
├── api/
│   ├── client.ts              # Axios instance
│   └── hooks.ts               # React Query hooks
├── stores/
│   ├── auth.ts                # Auth state
│   └── theme.ts               # Theme state
└── hooks/
    └── useWebSocket.ts        # Real-time updates
```

---

## 9. Real-time Updates

### 9.1 WebSocket Connection

```typescript
// hooks/useWebSocket.ts
export function useWebSocket(options: Options) {
  const accessToken = useAuthStore((state) => state.accessToken);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    // Build WebSocket URL with auth token
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/v1/ws?token=${accessToken}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      // Start keepalive ping
      setInterval(() => ws.send('ping'), 25000);
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      options.onMessage?.(message);
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Reconnect with exponential backoff
      setTimeout(connect, 3000 * Math.pow(2, reconnectAttempts));
    };
  }, [accessToken]);

  // Connect when authenticated
  useEffect(() => {
    if (accessToken) connect();
    return () => wsRef.current?.close();
  }, [accessToken, connect]);

  return { isConnected, sendMessage: (msg) => wsRef.current?.send(msg) };
}
```

### 9.2 Message Types

```typescript
type WebSocketMessageType =
  | 'alert_created'        // New alert generated
  | 'alert_updated'        // Alert status changed
  | 'device_status_changed' // Device quarantined/released
  | 'anomaly_detected'     // New anomaly found
  | 'system_notification'; // System message

interface WebSocketMessage<T> {
  type: WebSocketMessageType;
  data: T;
  timestamp: string;
}
```

### 9.3 Using Real-time Updates

```typescript
function AlertsPage() {
  const queryClient = useQueryClient();

  // Subscribe to WebSocket updates
  useWebSocket({
    onMessage: (message) => {
      if (message.type === 'alert_created') {
        // Show toast notification
        toast.warning(`New alert: ${message.data.title}`);
        // Refresh alerts list
        queryClient.invalidateQueries({ queryKey: ['alerts'] });
      }
    },
  });

  // ... rest of component
}
```

---

## 10. Automated Response

### 10.1 Playbook System

Playbooks define automated responses to alerts:

```python
class Playbook(Base):
    __tablename__ = "playbooks"

    name: str                    # "Quarantine Malware Sources"
    trigger_conditions: Dict     # When to run
    actions: List[Dict]          # What to do
    enabled: bool
```

**Trigger conditions:**
```json
{
  "alert_severity": ["critical", "high"],
  "anomaly_type": ["new_domain", "blocked_spike"],
  "device_tags": ["iot", "untrusted"]
}
```

**Actions:**
```json
{
  "actions": [
    {"type": "quarantine_device"},
    {"type": "send_notification", "config": {"channel": "email"}},
    {"type": "webhook", "config": {"url": "https://slack.example.com/hook"}}
  ]
}
```

### 10.2 Playbook Engine

```python
class PlaybookEngine:
    async def process_alert(self, alert: Alert):
        # Find matching playbooks
        playbooks = await self._get_matching_playbooks(alert)

        for playbook in playbooks:
            try:
                await self._execute_playbook(playbook, alert)
            except Exception as e:
                logger.error("playbook_execution_failed", error=str(e))

    async def _execute_playbook(self, playbook: Playbook, alert: Alert):
        for action in playbook.actions:
            if action["type"] == "quarantine_device":
                await self._quarantine_device(alert.device_id)

            elif action["type"] == "send_notification":
                await self._send_notification(alert, action["config"])

            elif action["type"] == "webhook":
                await self._call_webhook(alert, action["config"]["url"])
```

### 10.3 Quarantine Service

```python
class QuarantineService:
    async def quarantine_device(self, device_id: UUID, reason: str):
        device = await self._get_device(device_id)

        # Update device status
        device.status = DeviceStatus.QUARANTINED
        device.quarantine_reason = reason
        device.quarantined_at = datetime.now(timezone.utc)

        # Execute on router/firewall
        integration = self._get_router_integration()
        await integration.block_device(device.mac_address)

        # Execute on AdGuard (DNS blocking)
        if self._adguard_enabled:
            await self._adguard.block_client(device.ip_address)

        # Log audit event
        await self._create_audit_log(device_id, "quarantine", reason)
```

---

## 11. Complete Data Flow Walkthrough

Let's trace a complete flow from DNS query to alert:

### Step 1: DNS Query Occurs

A device on your network queries `suspicious-domain.com`.

### Step 2: AdGuard Home Logs It

AdGuard Home records the query in its query log.

### Step 3: Collector Fetches Data

```python
# Every 30 seconds, ApiPullCollector runs:
async def _poll_once(self):
    response = await self._client.get(
        "http://adguard/control/querylog",
        auth=("admin", "password")
    )
    return self.parser.parse(response.json())
```

### Step 4: Parser Normalizes

```python
# AdGuardParser extracts:
ParseResult(
    timestamp=datetime(2024, 1, 15, 10, 30, 0),
    event_type=EventType.DNS,
    severity=EventSeverity.INFO,
    client_ip="192.168.1.50",
    domain="suspicious-domain.com",
    action="allowed",
)
```

### Step 5: Event Stored

```python
# Worker creates RawEvent:
event = RawEvent(
    timestamp=result.timestamp,
    source_id=source.id,
    event_type=result.event_type,
    client_ip=result.client_ip,
    domain=result.domain,
    device_id=device.id,  # Resolved from IP
)
session.add(event)
```

### Step 6: Published to Redis

```python
# Event bus notifies subscribers:
await redis.xadd("events:stream", {
    "event_id": str(event.id),
    "event_type": "dns",
    "device_id": str(device.id),
})
```

### Step 7: Anomaly Detection Triggered

```python
# Anomaly detector runs:
async def detect_anomalies(self, device_id):
    baseline = await self._get_baseline(device_id)

    # Check: Is this domain new?
    if "suspicious-domain.com" not in baseline.metrics["unique_domains"]:
        return AnomalyDetection(
            anomaly_type=AnomalyType.NEW_DOMAIN,
            score=3.5,
            severity=AlertSeverity.MEDIUM,
            description="Device queried new domain: suspicious-domain.com",
        )
```

### Step 8: Alert Created

```python
# If severity >= MEDIUM:
alert = Alert(
    title="New Domain Detected",
    description="Device 192.168.1.50 queried suspicious-domain.com",
    severity=AlertSeverity.MEDIUM,
    device_id=device.id,
    status=AlertStatus.ACTIVE,
)
session.add(alert)
```

### Step 9: WebSocket Broadcast

```python
# Backend broadcasts to connected clients:
await websocket_manager.broadcast({
    "type": "alert_created",
    "data": {
        "id": str(alert.id),
        "title": alert.title,
        "severity": alert.severity.value,
    }
})
```

### Step 10: Frontend Updates

```typescript
// React component receives WebSocket message:
useWebSocket({
  onMessage: (msg) => {
    if (msg.type === 'alert_created') {
      toast.warning(`New alert: ${msg.data.title}`);
      queryClient.invalidateQueries(['alerts']);
    }
  }
});
```

### Step 11: Playbook Executes (If Configured)

```python
# Playbook engine checks for matches:
if alert.severity in playbook.trigger_conditions["alert_severity"]:
    for action in playbook.actions:
        if action["type"] == "send_notification":
            await send_email(
                to=admin_email,
                subject=f"Alert: {alert.title}",
                body=alert.description
            )
```

### Step 12: Optional: LLM Analysis

```python
# Semantic analysis service batches irregular logs:
result = await llm_provider.analyze_logs([
    {"message": "192.168.1.50 queried suspicious-domain.com"}
])

# Claude responds:
{
    "concerns": [{
        "severity": 0.7,
        "concern": "Domain appears on threat intelligence lists",
        "recommendation": "Investigate device for malware"
    }],
    "suggested_rules": [{
        "name": "Block Suspicious Domain Pattern",
        "rule_config": {"pattern": "*suspicious*.com"}
    }]
}
```

---

## Summary

You now understand:

1. **Collection**: How data enters via collectors (API, file, UDP)
2. **Parsing**: How different formats become unified ParseResults
3. **Storage**: How TimescaleDB efficiently stores time-series events
4. **Detection**: How baselines and z-scores identify anomalies
5. **AI Analysis**: How Claude/Ollama provide intelligent insights
6. **Security**: How auth, RBAC, and rate limiting protect the system
7. **Frontend**: How React, Zustand, and React Query power the UI
8. **Real-time**: How WebSockets push updates to clients
9. **Response**: How playbooks automate incident response

The system is designed to be:
- **Extensible**: Add new parsers/collectors with decorators
- **Scalable**: Async throughout, time-series database
- **Intelligent**: AI-powered analysis and rule suggestions
- **Automated**: Playbooks respond without human intervention
