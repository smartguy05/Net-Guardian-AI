# Configuration Reference

NetGuardian AI is configured via environment variables. All settings can be set in a `.env` file in the `deploy/` directory or exported as environment variables.

## Table of Contents

- [Application Settings](#application-settings)
- [Database Settings](#database-settings)
- [Redis Settings](#redis-settings)
- [HTTP Client Settings](#http-client-settings)
- [Rate Limiting](#rate-limiting)
- [Authentication](#authentication)
- [Authentik SSO Integration](#authentik-sso-integration)
- [CORS Settings](#cors-settings)
- [Log Ingestion](#log-ingestion)
- [AdGuard Home Integration](#adguard-home-integration)
- [Router Integration](#router-integration)
- [LLM Configuration](#llm-configuration)
- [Semantic Log Analysis](#semantic-log-analysis)
- [Ollama Monitoring](#ollama-monitoring)
- [Email Notifications](#email-notifications)
- [ntfy.sh Notifications](#ntfysh-notifications)

---

## Application Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APP_NAME` | string | `NetGuardian AI` | Application name displayed in UI |
| `DEBUG` | bool | `false` | Enable debug mode (enables API docs, verbose logging) |
| `LOG_LEVEL` | string | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Database Settings

NetGuardian uses TimescaleDB (PostgreSQL with time-series extensions).

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | `postgresql+asyncpg://netguardian:password@localhost:5432/netguardian` | PostgreSQL connection URL |
| `DB_POOL_SIZE` | int | `20` | Number of persistent connections in the pool |
| `DB_MAX_OVERFLOW` | int | `30` | Extra connections allowed beyond pool_size |
| `DB_POOL_TIMEOUT` | int | `30` | Seconds to wait for available connection |
| `DB_POOL_RECYCLE` | int | `1800` | Recycle connections after this many seconds |

### Example

```env
DATABASE_URL=postgresql+asyncpg://netguardian:securepassword@db:5432/netguardian
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
```

---

## Redis Settings

Redis is used for the event bus, caching, and rate limiting.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REDIS_URL` | string | `redis://localhost:6379/0` | Redis connection URL |
| `REDIS_MAX_CONNECTIONS` | int | `50` | Maximum connections in Redis pool |

---

## HTTP Client Settings

Settings for outbound HTTP connections to integrations.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `HTTP_TIMEOUT_SECONDS` | int | `30` | Request timeout in seconds |
| `HTTP_MAX_CONNECTIONS` | int | `100` | Maximum connections per host |
| `HTTP_KEEPALIVE_EXPIRY` | int | `30` | Seconds to keep idle connections |

---

## Rate Limiting

API rate limiting to prevent abuse.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `RATE_LIMIT_DEFAULT_RPM` | int | `60` | Requests per minute for default endpoints |
| `RATE_LIMIT_AUTH_RPM` | int | `10` | Requests per minute for auth endpoints |
| `RATE_LIMIT_CHAT_RPM` | int | `20` | Requests per minute for AI chat endpoints |
| `RATE_LIMIT_EXPORT_RPM` | int | `5` | Requests per minute for export endpoints |

---

## Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECRET_KEY` | string | (required) | JWT signing key. Generate with `openssl rand -hex 32` |
| `JWT_ALGORITHM` | string | `HS256` | JWT signing algorithm |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | int | `30` | Access token expiry in minutes |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | int | `7` | Refresh token expiry in days |

**Important:** Always set a secure `SECRET_KEY` in production!

---

## Authentik SSO Integration

Enable Single Sign-On (SSO) via Authentik identity provider using OAuth2/OIDC.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUTHENTIK_ENABLED` | bool | `false` | Enable Authentik SSO |
| `AUTHENTIK_ISSUER_URL` | string | `` | Authentik OIDC issuer URL (e.g., `https://auth.example.com/application/o/netguardian/`) |
| `AUTHENTIK_CLIENT_ID` | string | `` | OAuth2 client ID |
| `AUTHENTIK_CLIENT_SECRET` | string | `` | OAuth2 client secret |
| `AUTHENTIK_REDIRECT_URI` | string | `` | OAuth2 callback URL (e.g., `http://localhost:5173/auth/callback`) |
| `AUTHENTIK_SCOPES` | string | `openid profile email groups` | OAuth2 scopes to request |
| `AUTHENTIK_GROUP_MAPPINGS` | string | `{}` | JSON mapping of Authentik groups to NetGuardian roles |
| `AUTHENTIK_AUTO_CREATE_USERS` | bool | `true` | Automatically create users on first SSO login |
| `AUTHENTIK_DEFAULT_ROLE` | string | `viewer` | Default role for auto-created users |

### Setting Up Authentik

1. **Create an OAuth2/OIDC Provider in Authentik:**
   - Go to Applications > Providers > Create
   - Select "OAuth2/OIDC Provider"
   - Set Authorization flow and Client type to "Confidential"
   - Note the Client ID and Client Secret

2. **Create an Application:**
   - Go to Applications > Applications > Create
   - Link to your OAuth2/OIDC provider
   - Set the Launch URL to your NetGuardian frontend URL

3. **Configure Groups (optional):**
   - Create groups in Authentik (e.g., `netguardian-admins`, `netguardian-operators`)
   - Assign users to groups
   - Configure group mappings in NetGuardian

### Example Configuration

```env
AUTHENTIK_ENABLED=true
AUTHENTIK_ISSUER_URL=https://auth.example.com/application/o/netguardian/
AUTHENTIK_CLIENT_ID=netguardian-client-id
AUTHENTIK_CLIENT_SECRET=your-client-secret
AUTHENTIK_REDIRECT_URI=https://netguardian.example.com/auth/callback
AUTHENTIK_SCOPES=openid profile email groups
AUTHENTIK_GROUP_MAPPINGS={"netguardian-admins": "admin", "netguardian-operators": "operator"}
AUTHENTIK_AUTO_CREATE_USERS=true
AUTHENTIK_DEFAULT_ROLE=viewer
```

### Group to Role Mapping

The `AUTHENTIK_GROUP_MAPPINGS` setting maps Authentik groups to NetGuardian roles:

| Authentik Group | NetGuardian Role | Permissions |
|-----------------|------------------|-------------|
| `netguardian-admins` | `admin` | Full access |
| `netguardian-operators` | `operator` | Operational access |
| (default) | `viewer` | Read-only access |

Role priority: `admin` > `operator` > `viewer`. If a user belongs to multiple groups, the highest-priority role is assigned.

### User Provisioning Modes

NetGuardian supports two user provisioning modes for SSO:

**Mode 1: Auto-Create Users (Default)**
- Set `AUTHENTIK_AUTO_CREATE_USERS=true`
- Users are created automatically on first SSO login
- Role assigned from Authentik groups or `AUTHENTIK_DEFAULT_ROLE`
- Good for open enrollment or when Authentik controls access

**Mode 2: Pre-Create Users (Controlled Access)**
- Set `AUTHENTIK_AUTO_CREATE_USERS=false`
- Admin manually creates users in NetGuardian first
- User email must match their Authentik email
- On first SSO login, accounts are linked by email
- Only pre-approved users can access the system

**Pre-Create Workflow:**
1. Admin creates user in NetGuardian with desired role
2. User email must match their Authentik account email
3. User clicks "Sign in with Authentik" on login page
4. System links accounts by email match
5. User is logged in with their NetGuardian role

This mode is recommended when you want to control exactly who can access NetGuardian, rather than granting access to anyone in Authentik.

### Authentik Event Log Collection

You can also collect Authentik's event logs as a log source:

```bash
curl -X POST http://localhost:8000/api/v1/sources \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "authentik-events",
    "name": "Authentik Events",
    "source_type": "api_pull",
    "parser_type": "authentik",
    "config": {
      "url": "https://auth.example.com",
      "endpoint": "/api/v3/events/",
      "auth_type": "bearer",
      "api_key": "your-authentik-api-token",
      "poll_interval_seconds": 60
    }
  }'
```

This monitors authentication events (logins, failures, impersonation, etc.) from your Authentik instance.

---

## CORS Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CORS_ORIGINS` | list | `["http://localhost:3000", "http://localhost:5173"]` | Allowed CORS origins (JSON array or comma-separated) |

### Example

```env
# JSON format
CORS_ORIGINS=["https://netguardian.example.com"]

# Comma-separated
CORS_ORIGINS=https://netguardian.example.com,https://admin.example.com
```

---

## Log Ingestion

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_SOURCES_DIR` | string | `/logs` | Directory for file-based log sources |
| `LOG_INGESTION_API_ENABLED` | bool | `true` | Enable API-based log ingestion |
| `LOG_INGESTION_RATE_LIMIT` | int | `1000` | Events per minute per source |

---

## AdGuard Home Integration

Enable DNS-level device blocking via AdGuard Home.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ADGUARD_ENABLED` | bool | `false` | Enable AdGuard Home integration |
| `ADGUARD_URL` | string | `` | AdGuard Home URL (e.g., `http://192.168.1.1:3000`) |
| `ADGUARD_USERNAME` | string | `` | AdGuard admin username |
| `ADGUARD_PASSWORD` | string | `` | AdGuard admin password |
| `ADGUARD_VERIFY_SSL` | bool | `true` | Verify SSL certificates |

### Example

```env
ADGUARD_ENABLED=true
ADGUARD_URL=http://192.168.1.1:3000
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=securepassword
```

---

## Router Integration

Enable device quarantine via router firewall rules.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ROUTER_INTEGRATION_TYPE` | string | `` | Router type: `unifi`, `pfsense`, `opnsense`, `ssh` |
| `ROUTER_URL` | string | `` | Router management URL |
| `ROUTER_USERNAME` | string | `` | Router admin username |
| `ROUTER_PASSWORD` | string | `` | Router admin password |
| `ROUTER_SITE` | string | `default` | UniFi site name (UniFi only) |
| `ROUTER_VERIFY_SSL` | bool | `true` | Verify SSL certificates |

### UniFi Example

```env
ROUTER_INTEGRATION_TYPE=unifi
ROUTER_URL=https://192.168.1.1:8443
ROUTER_USERNAME=admin
ROUTER_PASSWORD=securepassword
ROUTER_SITE=default
```

### pfSense Example

```env
ROUTER_INTEGRATION_TYPE=pfsense
ROUTER_URL=https://192.168.1.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=securepassword
```

---

## LLM Configuration

Configure Anthropic Claude for AI-powered analysis.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ANTHROPIC_API_KEY` | string | `` | Anthropic API key |
| `LLM_ENABLED` | bool | `true` | Enable LLM features |
| `LLM_MODEL_DEFAULT` | string | `claude-sonnet-4-latest` | Model for general analysis |
| `LLM_MODEL_FAST` | string | `claude-3-5-haiku-latest` | Model for quick triage |
| `LLM_MODEL_DEEP` | string | `claude-sonnet-4-latest` | Model for detailed analysis |
| `LLM_MAX_TOKENS` | int | `4096` | Maximum tokens per response |
| `LLM_TEMPERATURE` | float | `0.3` | Model temperature (0-1) |
| `LLM_CACHE_ENABLED` | bool | `true` | Enable Anthropic prompt caching |

### Example

```env
ANTHROPIC_API_KEY=sk-ant-...
LLM_ENABLED=true
LLM_MODEL_DEFAULT=claude-sonnet-4-latest
```

---

## Semantic Log Analysis

AI-powered analysis of log content to identify unusual patterns and suggest detection rules.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SEMANTIC_ANALYSIS_ENABLED` | bool | `true` | Enable semantic log analysis feature globally |
| `SEMANTIC_DEFAULT_LLM_PROVIDER` | string | `claude` | Default LLM provider: `claude` or `ollama` |
| `SEMANTIC_DEFAULT_RARITY_THRESHOLD` | int | `3` | Patterns seen fewer than N times are irregular |
| `SEMANTIC_DEFAULT_BATCH_SIZE` | int | `50` | Maximum logs per LLM analysis batch |
| `SEMANTIC_DEFAULT_BATCH_INTERVAL_MINUTES` | int | `60` | Minutes between automated analysis runs |
| `SEMANTIC_SCHEDULER_ENABLED` | bool | `true` | Enable background scheduler for periodic analysis |
| `OLLAMA_DEFAULT_MODEL` | string | `llama3.2` | Default Ollama model for semantic analysis |
| `OLLAMA_TIMEOUT_SECONDS` | int | `120` | Timeout for Ollama API requests |

### Example

```env
# Enable semantic analysis with Claude
SEMANTIC_ANALYSIS_ENABLED=true
SEMANTIC_DEFAULT_LLM_PROVIDER=claude
SEMANTIC_DEFAULT_RARITY_THRESHOLD=3
SEMANTIC_DEFAULT_BATCH_SIZE=50
SEMANTIC_DEFAULT_BATCH_INTERVAL_MINUTES=60

# Or use local Ollama
SEMANTIC_DEFAULT_LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_DEFAULT_MODEL=llama3.2
OLLAMA_TIMEOUT_SECONDS=120
```

### Per-Source Configuration

Each log source can have its own semantic analysis settings configured via the API or UI:

```json
{
  "enabled": true,
  "llm_provider": "claude",
  "ollama_model": "llama3.2",
  "rarity_threshold": 5,
  "batch_size": 100,
  "batch_interval_minutes": 30
}
```

---

## Ollama Monitoring

Monitor local Ollama LLM instances for prompt injection attacks.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OLLAMA_ENABLED` | bool | `false` | Enable Ollama monitoring |
| `OLLAMA_URL` | string | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_POLL_INTERVAL_SECONDS` | int | `30` | Polling interval |
| `OLLAMA_VERIFY_SSL` | bool | `false` | Verify SSL certificates |
| `OLLAMA_DETECTION_ENABLED` | bool | `true` | Enable injection detection |
| `OLLAMA_PROMPT_ANALYSIS_ENABLED` | bool | `true` | Use Claude to analyze prompts |
| `OLLAMA_ALERT_ON_INJECTION` | bool | `true` | Create alerts for detected attacks |
| `OLLAMA_INJECTION_SEVERITY` | string | `high` | Alert severity for injections |
| `OLLAMA_DEFAULT_MODEL` | string | `llama3.2` | Default model for semantic analysis |
| `OLLAMA_TIMEOUT_SECONDS` | int | `120` | Timeout for Ollama API requests |

---

## Email Notifications

Configure SMTP for email alerts.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | string | `` | SMTP server hostname |
| `SMTP_PORT` | int | `587` | SMTP server port |
| `SMTP_USERNAME` | string | `` | SMTP username |
| `SMTP_PASSWORD` | string | `` | SMTP password |
| `SMTP_USE_TLS` | bool | `true` | Use TLS encryption |
| `SMTP_SENDER_EMAIL` | string | `` | Sender email address |
| `SMTP_SENDER_NAME` | string | `NetGuardian AI` | Sender display name |

### Gmail Example

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=app-specific-password
SMTP_USE_TLS=true
SMTP_SENDER_EMAIL=your-email@gmail.com
```

---

## ntfy.sh Notifications

Configure ntfy.sh for push notifications.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NTFY_SERVER_URL` | string | `https://ntfy.sh` | ntfy server URL (public or self-hosted) |
| `NTFY_DEFAULT_TOPIC` | string | `` | Default notification topic |
| `NTFY_AUTH_TOKEN` | string | `` | Optional auth token for private topics |

### Example

```env
# Public ntfy.sh
NTFY_SERVER_URL=https://ntfy.sh
NTFY_DEFAULT_TOPIC=my-netguardian-alerts

# Self-hosted
NTFY_SERVER_URL=https://ntfy.example.com
NTFY_DEFAULT_TOPIC=netguardian
NTFY_AUTH_TOKEN=tk_...
```

---

## Complete Example

Here's a complete `.env` file for production:

```env
# Application
APP_NAME=NetGuardian AI
DEBUG=false
LOG_LEVEL=INFO

# Database
DATABASE_URL=postgresql+asyncpg://netguardian:securepassword@db:5432/netguardian
DB_POOL_SIZE=20

# Redis
REDIS_URL=redis://redis:6379/0

# Security
SECRET_KEY=your-256-bit-secret-key-here
CORS_ORIGINS=["https://netguardian.example.com"]

# AdGuard
ADGUARD_ENABLED=true
ADGUARD_URL=http://192.168.1.1:3000
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=securepassword

# Router
ROUTER_INTEGRATION_TYPE=unifi
ROUTER_URL=https://192.168.1.1:8443
ROUTER_USERNAME=admin
ROUTER_PASSWORD=securepassword

# LLM
ANTHROPIC_API_KEY=sk-ant-...
LLM_ENABLED=true

# Semantic Analysis
SEMANTIC_ANALYSIS_ENABLED=true
SEMANTIC_DEFAULT_LLM_PROVIDER=claude
SEMANTIC_DEFAULT_BATCH_INTERVAL_MINUTES=60

# Notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=app-password
SMTP_SENDER_EMAIL=alerts@example.com

NTFY_SERVER_URL=https://ntfy.sh
NTFY_DEFAULT_TOPIC=my-netguardian
```

---

## Environment-Specific Configuration

### Development

```env
DEBUG=true
LOG_LEVEL=DEBUG
DATABASE_URL=postgresql+asyncpg://netguardian:password@localhost:5432/netguardian
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000"]
```

### Production

- Always set `DEBUG=false`
- Use strong, unique `SECRET_KEY`
- Enable SSL verification for all integrations
- Configure proper CORS origins
- Use environment variables (not `.env` files) when possible

### Docker Deployment

When using Docker Compose, environment variables can be set in the `deploy/.env` file or passed via the compose file:

```yaml
services:
  backend:
    environment:
      - DATABASE_URL=postgresql+asyncpg://netguardian:${DB_PASSWORD}@db:5432/netguardian
      - SECRET_KEY=${SECRET_KEY}
```
