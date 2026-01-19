# NetGuardian AI

## Product Requirements Document

**AI-Powered Home Network Security Monitoring System**

Version 1.1 | January 2026 | Author: Anthony

**Revision History:**
- v1.1 (Jan 2026): Added multi-source log ingestion, user management with RBAC, JWT authentication details
- v1.0 (Jan 2026): Initial PRD

---

## 1. Executive Summary

NetGuardian AI is a self-hosted, AI-powered network security monitoring system designed for home and small office environments. The system continuously monitors network traffic, DNS queries, and device behavior to detect potential security threats, including the emerging class of LLM-powered malware such as PromptLock.

The system integrates with existing infrastructure (AdGuard Home, consumer routers) and leverages Anthropic's Claude API for intelligent threat analysis and natural language interaction. When threats are detected, NetGuardian AI can automatically quarantine suspicious devices and alert the user through multiple channels.

### 1.1 Key Value Propositions

- Proactive threat detection using behavioral analysis and ML-based anomaly detection
- Specific detection capabilities for LLM-powered malware (Ollama API monitoring, model enumeration detection)
- Claude API integration for intelligent alert triage and natural language querying
- Automated response capabilities including DNS blocking and device quarantine
- Privacy-conscious design with minimal data sent to cloud (metadata only, optional fully-local mode)

---

## 2. Problem Statement

### 2.1 The Emerging LLM Malware Threat

In August 2025, security researchers discovered PromptLock, the first AI-powered ransomware proof-of-concept. This malware represents a paradigm shift in threat sophistication:

- Uses locally-hosted LLMs (via Ollama API) to dynamically generate malicious code at runtime
- Generates Lua scripts that vary with each execution, evading signature-based detection
- Can autonomously determine whether to exfiltrate, encrypt, or destroy data based on context
- Cross-platform compatibility (Windows, Linux, macOS)

Anthropic's August 2025 threat intelligence report documented real-world attacks using AI tools for reconnaissance, credential harvesting, and network penetration across healthcare, government, and emergency services organizations.

### 2.2 Current Home Network Security Gaps

- Consumer routers provide minimal security visibility beyond basic firewall rules
- Ad blockers like AdGuard Home focus on content filtering, not security monitoring
- No affordable solutions correlate behavioral signals across devices and time
- Traditional endpoint security doesn't monitor for AI-specific threat indicators
- Most home users lack the expertise to interpret raw security logs

### 2.3 Target User

Technical home users and small business operators who run self-hosted services (NAS, media servers, home automation) and want enterprise-grade security monitoring without cloud dependencies or subscription fees.

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. Provide continuous, automated monitoring of home network security posture
2. Detect anomalous device behavior that may indicate compromise
3. Specifically identify indicators of LLM-powered malware activity
4. Provide automated quarantine capabilities for compromised devices
5. Deliver actionable, understandable alerts to non-security-expert users
6. Enable natural language queries about network state and security events
7. Minimize data exposure with metadata-only cloud transmission (optional fully-local mode available)

### 3.2 Non-Goals

- Replacing endpoint antivirus/EDR solutions
- Deep packet inspection of encrypted traffic
- Active penetration testing or vulnerability scanning of devices
- Cloud-based threat intelligence sharing (privacy concern)
- Enterprise-scale deployments (>100 devices)
- Compliance reporting (HIPAA, PCI-DSS, etc.)

---

## 4. System Architecture

### 4.1 High-Level Architecture

The system follows a modular, event-driven architecture with five primary layers:

| Layer | Description |
|-------|-------------|
| Collection | Gathers data from AdGuard Home, network flows, and optional endpoint agents |
| Ingestion | Normalizes, enriches, and streams events through Redis |
| Analysis | Applies ML models, rule engine, and LLM reasoning |
| Response | Executes automated actions and sends alerts |
| Presentation | Dashboard, API, and chat interface |

### 4.2 Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA SOURCES                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  AdGuard Home API    │   Network Monitor    │   Endpoint Agents (opt)   │
│  - Query logs        │   - NetFlow/sFlow    │   - Process monitoring    │
│  - Statistics        │   - Connection state │   - Ollama API calls      │
│  - Client info       │   - Bandwidth        │   - File system events    │
└──────────┬───────────┴─────────┬────────────┴──────────┬────────────────┘
           │                     │                       │
           └─────────────────────┼───────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │  Collectors     │  │  Normalizer     │  │  Enricher       │          │
│  │  (Polling/Push) │─▶│  (Schema)       │─▶│  (GeoIP, etc)   │          │
│  └─────────────────┘  └─────────────────┘  └────────┬────────┘          │
└────────────────────────────────────────────────────┬────────────────────┘
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EVENT BUS (Redis Streams)                        │
└────────────────────────────────────────────────────┬────────────────────┘
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ANALYSIS LAYER                                   │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                │
│  │  Baseline     │  │  Anomaly      │  │  Rule         │                │
│  │  Engine       │  │  Detector     │  │  Engine       │                │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘                │
│          │                  │                  │                         │
│          └──────────────────┼──────────────────┘                         │
│                             ▼                                            │
│                    ┌───────────────┐                                     │
│                    │  LLM Analyzer │                                     │
│                    │  (Claude API) │                                     │
│                    └───────┬───────┘                                     │
└────────────────────────────┬────────────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        RESPONSE LAYER                                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                │
│  │  Alert        │  │  Action       │  │  Audit        │                │
│  │  Manager      │  │  Executor     │  │  Logger       │                │
│  └───────────────┘  └───────────────┘  └───────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Functional Requirements

### 5.1 Data Collection (FR-DC)

The system supports three primary methods for log/event ingestion:

#### FR-DC-001: API Pull Collection
The system shall support pulling logs from external REST APIs with configurable:
- **Authentication**: None, Basic Auth, Bearer Token, API Key, or custom headers
- **Polling interval**: Configurable per source (default: 5-30 seconds)
- **Pagination**: Cursor-based, offset-based, or timestamp-based pagination
- **Built-in integrations**: AdGuard Home, UniFi Controller, pfSense (with extensible parser framework)

#### FR-DC-002: File-Based Collection
The system shall support monitoring mounted log directories with:
- **File watching**: Real-time tail -f style monitoring using the watchdog library
- **Log formats**: Syslog (RFC 3164/5424), JSON, Nginx access/error logs, custom regex patterns
- **Docker volume mounts**: Log directories mounted into the collector container

#### FR-DC-003: API Push Collection
The system shall provide HTTP endpoints for external services to push logs:
- **Endpoints**: `/api/v1/logs/ingest` for single/batch events, format-specific endpoints for syslog/JSON
- **Authentication**: Auto-generated API keys per push source
- **Rate limiting**: Configurable events per minute per source (default: 1000)

#### FR-DC-004: Device Inventory
The system shall maintain an inventory of all network devices including MAC address, IP address(es), hostname, first seen timestamp, last seen timestamp, device type (if identifiable), and manufacturer (via OUI lookup).

#### FR-DC-005: Endpoint Agent (Optional)
The system shall support optional lightweight endpoint agents that report process lists and network connections (Linux/macOS), Ollama API activity monitoring, and file system events in monitored directories.

#### FR-DC-006: Log Source Configuration
The system shall provide a management interface for configuring log sources including:
- Create, update, enable/disable, and delete sources via API and UI
- Test connectivity and parsing for new sources
- Monitor source health (last event timestamp, error status, event counts)

### 5.2 Baseline & Anomaly Detection (FR-AD)

#### FR-AD-001: Device Behavioral Baseline
The system shall build per-device behavioral profiles including typical DNS query patterns (domains, frequency, timing), normal traffic volumes and protocols, usual active hours, and common connection destinations.

#### FR-AD-002: Baseline Learning Period
The system shall require a minimum 7-day learning period before generating anomaly alerts, with an option to extend or reset the learning period per device.

#### FR-AD-003: Statistical Anomaly Detection
The system shall detect statistical anomalies using z-score analysis for volume-based metrics, Isolation Forest for multivariate outliers, and time-series analysis for temporal patterns.

#### FR-AD-004: DNS Anomaly Detection
The system shall specifically detect high-entropy domain queries (potential DGA), unusually long subdomain strings (potential exfiltration), sudden increase in unique domains queried, and DNS queries to known malicious categories (via threat feeds).

#### FR-AD-005: Connection Anomaly Detection
The system shall detect new outbound connections to previously unseen destinations, connections to uncommon ports (especially >1024), unusual protocol usage for a device type, and lateral movement patterns between internal devices.

### 5.3 LLM-Malware Specific Detection (FR-LM)

#### FR-LM-001: Ollama API Monitoring
The system shall detect and alert on Ollama API traffic (default port 11434) from devices not explicitly whitelisted as AI workstations.

#### FR-LM-002: Model Enumeration Detection
The system shall alert on rapid model pull requests (>3 within 5 minutes) to the /api/pull endpoint, which indicates potential reconnaissance.

#### FR-LM-003: Lua Execution Monitoring
When endpoint agents are deployed, the system shall alert on Lua interpreter execution on devices not profiled as gaming systems.

#### FR-LM-004: LLM API Call Pattern Analysis
When endpoint agents are deployed, the system shall analyze Ollama API call patterns and flag prompts consistent with known malware behaviors (file enumeration, PII detection, encryption requests).

### 5.4 LLM-Powered Analysis (FR-LA)

#### FR-LA-001: Alert Triage
The system shall use Claude API to analyze alerts and provide confidence scoring (0-100), plain-language explanation of the threat, recommended actions, and correlation with other recent events.

#### FR-LA-002: Natural Language Querying
The system shall support natural language queries about network state such as "What unusual activity has my NAS shown today?", "Which devices have connected to new destinations this week?", and "Show me a summary of blocked DNS queries".

#### FR-LA-003: Incident Summarization
The system shall generate human-readable incident summaries that can be used for documentation or sharing with support personnel.

#### FR-LA-004: LLM Model Support
The system shall support Anthropic Claude API as the primary LLM integration, with Claude Sonnet 4 recommended for the optimal balance of speed, cost, and capability. Optional Ollama integration shall be available for users who prefer fully local processing.

#### FR-LA-005: Prompt Caching
The system shall implement Anthropic's prompt caching feature to optimize API usage. Static prompt components (system instructions, detection rule definitions, baseline context templates) shall be cached and reused across requests. Cache-eligible content shall be structured with stable prefixes to maximize cache hit rates.

### 5.5 Response Actions (FR-RA)

#### FR-RA-001: Alert Severity Levels
The system shall classify alerts into four severity levels: INFO (logged, no notification), LOW (logged, optional notification), MEDIUM (notification required), HIGH (notification + automated response option), and CRITICAL (immediate notification + automated response).

#### FR-RA-002: Notification Channels
The system shall support push notifications via ntfy.sh or Pushover, email notifications via SMTP, webhook integration for custom automation, and in-app notification center.

#### FR-RA-003: DNS-Level Blocking
The system shall be able to add devices to AdGuard Home's blocked clients list, effectively cutting off their DNS resolution.

#### FR-RA-004: Router-Level Quarantine
The system shall support MAC-based blocking via router APIs for UniFi, pfSense/OPNsense, and generic routers with SSH access.

#### FR-RA-005: Quarantine Management
The system shall maintain a quarantine list with reason, timestamp, and releasing user. Quarantined devices shall remain blocked until manually released.

#### FR-RA-006: Response Playbooks
The system shall support configurable response playbooks that define automatic actions based on alert type and severity.

### 5.6 User Interface (FR-UI)

#### FR-UI-001: Dashboard
The system shall provide a web-based dashboard showing network health overview with device count and threat summary, real-time event feed, device inventory with status indicators, alert timeline and history, and quarantine status panel.

#### FR-UI-002: Device Detail View
Each device shall have a detail page showing identification information, behavioral baseline summary, recent activity timeline, anomaly score history, and action buttons (quarantine, whitelist, investigate).

#### FR-UI-003: Chat Interface
The system shall provide a chat interface for natural language interaction with the LLM analyzer, accessible from the dashboard.

#### FR-UI-004: Configuration UI
The system shall provide configuration interfaces for data source connections, detection rule management, notification preferences, response playbook editor, and whitelist management.

#### FR-UI-005: Mobile Responsiveness
The dashboard shall be responsive and usable on mobile devices for alert review and basic actions.

---

## 6. Data Models

### 6.1 Core Entities

#### User

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| username | String | Unique username (lowercase) |
| email | String | Unique email address |
| password_hash | String | Bcrypt hashed password (never plain text) |
| role | Enum | admin, operator, viewer |
| is_active | Boolean | Whether account is active |
| must_change_password | Boolean | Force password change on next login |
| last_login | DateTime | Last successful login timestamp |
| created_by | UUID | Admin who created this account |
| created_at | DateTime | Account creation timestamp |

#### Device

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| mac_address | String | Primary MAC address |
| ip_addresses | String[] | Known IP addresses (may change) |
| hostname | String | Device hostname |
| manufacturer | String | From OUI lookup |
| device_type | Enum | pc, mobile, iot, server, network, unknown |
| profile_tags | String[] | User-defined tags (e.g., 'ai_workstation', 'gaming') |
| first_seen | DateTime | First observed timestamp |
| last_seen | DateTime | Most recent activity |
| status | Enum | active, inactive, quarantined |
| baseline_ready | Boolean | Has completed baseline learning |

#### LogSource

| Field | Type | Description |
|-------|------|-------------|
| id | String | Unique identifier (slug) |
| name | String | Human-readable display name |
| description | String | Optional description |
| source_type | Enum | api_pull, file_watch, api_push |
| enabled | Boolean | Whether source is active |
| config | JSON | Source-specific configuration |
| parser_type | Enum | adguard, unifi, pfsense, json, syslog, nginx, custom |
| parser_config | JSON | Parser-specific configuration |
| api_key | String | Auto-generated key for push sources |
| last_event_at | DateTime | Timestamp of last received event |
| last_error | String | Last error message if any |
| event_count | Integer | Total events received |

#### RawEvent (TimescaleDB Hypertable)

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| timestamp | DateTime | Event timestamp (partition key) |
| source_id | String | Reference to LogSource |
| event_type | Enum | dns, firewall, auth, http, system, network |
| severity | Enum | debug, info, warning, error, critical |
| client_ip | String | Source IP address |
| target_ip | String | Destination IP address |
| domain | String | Domain name if applicable |
| port | Integer | Port number if applicable |
| protocol | String | TCP, UDP, etc. |
| action | String | allow, block, drop, etc. |
| raw_message | String | Original log line |
| parsed_fields | JSON | Additional parsed fields |
| device_id | UUID | Associated device (resolved from IP) |

#### Alert

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| timestamp | DateTime | Alert creation time |
| device_id | UUID | Related device |
| rule_id | String | Detection rule that triggered |
| severity | Enum | info, low, medium, high, critical |
| title | String | Short alert title |
| description | String | Detailed description |
| llm_analysis | JSON | LLM-generated analysis (if performed) |
| status | Enum | new, acknowledged, resolved, false_positive |
| actions_taken | JSON[] | Log of response actions |
| acknowledged_by | UUID | User who acknowledged |
| resolved_by | UUID | User who resolved |

### 6.2 Detection Rule Schema

```json
{
  "id": "ollama_unexpected_traffic",
  "name": "Unexpected Ollama API Traffic",
  "description": "Detects Ollama API traffic from non-whitelisted devices",
  "severity": "high",
  "enabled": true,
  "conditions": {
    "all": [
      { "field": "connection.dest_port", "operator": "eq", "value": 11434 },
      { "field": "device.profile_tags", "operator": "not_contains", "value": "ai_workstation" }
    ]
  },
  "response_actions": [
    { "type": "notify", "channels": ["push", "email"] },
    { "type": "quarantine", "requires_confirmation": true }
  ],
  "cooldown_minutes": 60
}
```

---

## 7. API Specification

### 7.1 REST API Endpoints

The system shall expose a RESTful API for programmatic access. All endpoints (except auth) require JWT authentication.

#### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | /api/v1/auth/login | Login with username/password | No |
| POST | /api/v1/auth/logout | Invalidate current session | Yes |
| POST | /api/v1/auth/refresh | Refresh access token | Yes (refresh token) |
| GET | /api/v1/auth/me | Get current user info | Yes |
| PATCH | /api/v1/auth/password | Change own password | Yes |

#### User Management (Admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/users | List all users |
| POST | /api/v1/users | Create new user |
| GET | /api/v1/users/{id} | Get user details |
| PATCH | /api/v1/users/{id} | Update user (role, active status) |
| DELETE | /api/v1/users/{id} | Deactivate user |
| POST | /api/v1/users/{id}/reset-password | Admin reset password |

#### Device Management

| Method | Endpoint | Description | Min Role |
|--------|----------|-------------|----------|
| GET | /api/v1/devices | List all devices with filtering/pagination | Viewer |
| GET | /api/v1/devices/{id} | Get device details and recent activity | Viewer |
| PATCH | /api/v1/devices/{id} | Update device (tags, type, name) | Operator |
| POST | /api/v1/devices/{id}/quarantine | Quarantine a device | Operator |
| DELETE | /api/v1/devices/{id}/quarantine | Release device from quarantine | Operator |

#### Alert Management

| Method | Endpoint | Description | Min Role |
|--------|----------|-------------|----------|
| GET | /api/v1/alerts | List alerts with filtering | Viewer |
| GET | /api/v1/alerts/{id} | Get alert details | Viewer |
| PATCH | /api/v1/alerts/{id} | Update alert status | Operator |
| POST | /api/v1/alerts/{id}/analyze | Request LLM analysis | Viewer |

#### Log Source Management (Admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/sources | List configured log sources |
| POST | /api/v1/sources | Create new log source |
| GET | /api/v1/sources/{id} | Get source details |
| PUT | /api/v1/sources/{id} | Update source configuration |
| DELETE | /api/v1/sources/{id} | Remove source |
| POST | /api/v1/sources/{id}/test | Test source connectivity/parsing |

#### Log Ingestion (Push Sources)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | /api/v1/logs/ingest | Push single event or batch | Source API Key |
| POST | /api/v1/logs/ingest/syslog | Syslog-formatted events | Source API Key |
| POST | /api/v1/logs/ingest/json | JSON-formatted events | Source API Key |

#### Query & Analysis

| Method | Endpoint | Description | Min Role |
|--------|----------|-------------|----------|
| POST | /api/v1/query | Natural language query | Viewer |
| GET | /api/v1/stats/overview | Dashboard statistics | Viewer |
| GET | /api/v1/events | Query event history (all sources) | Viewer |
| GET | /api/v1/events/dns | Query DNS event history | Viewer |

### 7.2 WebSocket API

The system shall provide WebSocket endpoints for real-time updates:

- `/ws/events` - Real-time event stream (DNS queries, connections)
- `/ws/alerts` - Real-time alert notifications
- `/ws/chat` - Streaming LLM responses for chat interface

---

## 8. Technology Stack

### 8.1 Core Technologies

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Backend Framework | Python 3.12 + FastAPI | Async-native, excellent ML ecosystem, rapid development |
| Time-Series DB | TimescaleDB | PostgreSQL-compatible, excellent for time-series with SQL |
| Message Queue | Redis Streams | Lightweight, supports consumer groups, pub/sub |
| ML Runtime | scikit-learn + PyTorch | Anomaly detection models, optional deep learning |
| Primary LLM | Anthropic Claude API | Best-in-class reasoning, excellent for security analysis |
| Local LLM (Optional) | Ollama | Fallback for offline/privacy-sensitive deployments |
| Frontend | React + TypeScript | Component ecosystem, TypeScript safety, wide adoption |
| Dashboard Charts | Recharts / Apache ECharts | React-native, good time-series support |
| Containerization | Docker + Docker Compose | Standard deployment, easy updates |

### 8.2 External Integrations

| Integration | Protocol | Purpose |
|-------------|----------|---------|
| AdGuard Home | REST API | DNS logs, statistics, blocking |
| UniFi Controller | REST API | Device quarantine (optional) |
| pfSense/OPNsense | REST API / XML-RPC | Firewall rules, device quarantine |
| Generic Routers | SSH | Fallback for device blocking |
| ntfy.sh | HTTP POST | Push notifications |
| Threat Feeds | HTTP GET | abuse.ch, Emerging Threats |

### 8.3 Recommended LLM Models

| Model | Type | Cost (per 1M tokens) | Use Case |
|-------|------|----------------------|----------|
| Claude Sonnet 4 | Cloud API | $3 in / $15 out | Primary: Best balance of speed and capability |
| Claude Haiku 4 | Cloud API | $0.80 in / $4 out | High-volume: Fast triage, simple queries |
| Claude Opus 4 | Cloud API | $15 in / $75 out | Complex: Deep incident analysis |
| Llama 3.3 70B | Local (Ollama) | Free (hardware) | Optional: Fully offline operation |
| Qwen 2.5 32B | Local (Ollama) | Free (hardware) | Optional: Local with less VRAM |

---

## 9. Security Considerations

### 9.1 Authentication & Authorization

#### User Management
- **Local accounts only**: Username/password stored in database (OIDC deferred to future release)
- **Password security**: Bcrypt hashing with salt - passwords are NEVER stored in plain text
- **Initial admin**: First run creates default admin with random password printed to logs
- **Password policy**: Admin must change password on first login

#### JWT Authentication
- **Access tokens**: Short-lived JWT tokens (default: 30 minutes)
- **Refresh tokens**: Long-lived tokens for session continuity (default: 7 days)
- **Token rotation**: Refresh tokens are rotated on use
- **Algorithm**: HS256 with configurable secret key

#### Role-Based Access Control (RBAC)

| Permission | Admin | Operator | Viewer |
|------------|-------|----------|--------|
| View dashboard, devices, events | Yes | Yes | Yes |
| Query statistics | Yes | Yes | Yes |
| Acknowledge alerts | Yes | Yes | No |
| Quarantine/release devices | Yes | Yes | No |
| Modify device tags/settings | Yes | Yes | No |
| Configure log sources | Yes | No | No |
| Manage detection rules | Yes | No | No |
| Manage users | Yes | No | No |
| System configuration | Yes | No | No |

### 9.2 Data Protection

- Network logs and device data stored locally - only anonymized metadata sent to Claude API
- Optional fully-local mode using Ollama for privacy-sensitive deployments
- Sensitive credentials (router passwords, API keys) encrypted at rest using AES-256
- Database connections use TLS where supported
- Audit log of all administrative actions

### 9.3 Network Security

- Dashboard accessible only via HTTPS (self-signed or Let's Encrypt)
- Service binds to localhost by default; explicit configuration required for network access
- Rate limiting on API endpoints

### 9.4 LLM Security

- Anthropic API key stored encrypted at rest, never exposed to frontend
- Prompts shall not include raw user credentials, API keys, or excessive PII
- Data sent to Claude API limited to network metadata and anomaly context (not full packet captures)
- LLM responses validated before executing any suggested actions
- No automatic execution of LLM-generated code
- Optional: Ollama fallback for users requiring fully offline operation

---

## 10. Implementation Phases

### Phase 1: Foundation (Weeks 1-3)

**Goal:** Establish data collection and basic monitoring

- Project scaffolding (Docker Compose, directory structure)
- AdGuard Home API integration
- TimescaleDB schema and migrations
- Device inventory management
- Basic REST API endpoints
- Simple dashboard with device list and event feed

**Deliverable:** Working system that collects and displays DNS data

### Phase 2: Anomaly Detection (Weeks 4-6)

**Goal:** Implement behavioral baselines and anomaly detection

- Baseline engine for per-device behavior profiles
- Statistical anomaly detection (z-score, IQR)
- DNS-specific detections (entropy, DGA patterns)
- Rule engine for configurable detection rules
- Alert generation and notification pipeline

**Deliverable:** System generates alerts for anomalous behavior

### Phase 3: LLM Integration (Weeks 7-9)

**Goal:** Add intelligent analysis and natural language interface

- Anthropic Claude API integration service with prompt caching
- Model selection logic (Haiku for triage, Sonnet for analysis)
- Cache-optimized prompt templates with stable prefixes
- Alert triage prompts and analysis pipeline
- Natural language query interface
- Chat UI component
- Incident summarization

**Deliverable:** LLM-powered alert analysis and chat interface

### Phase 4: Active Response (Weeks 10-12)

**Goal:** Implement automated response capabilities

- AdGuard Home blocking integration
- Router integration (UniFi, pfSense)
- Response playbook engine
- Quarantine management UI
- Audit logging

**Deliverable:** Full automated response capability

### Phase 5: Polish & Extensions (Weeks 13-16)

**Goal:** Production readiness and additional features

- LLM-malware specific detections (Ollama monitoring)
- Optional endpoint agent
- NetFlow/sFlow integration
- Performance optimization
- Documentation and deployment guides
- Security hardening review

**Deliverable:** Production-ready release

---

## 11. Success Metrics

### 11.1 Functional Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| DNS event ingestion rate | >1000 events/sec | Load testing |
| Alert generation latency | <5 seconds | End-to-end timing |
| LLM analysis latency (Claude API) | <10 seconds | API response timing |
| Dashboard load time | <2 seconds | Browser metrics |
| System uptime | >99.5% | Health checks |

### 11.2 Detection Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| False positive rate | <5% after baseline | User feedback |
| Detection of simulated threats | >90% | Red team testing |
| Time to detect DGA traffic | <1 minute | Synthetic testing |
| Time to detect Ollama abuse | <5 minutes | Synthetic testing |

---

## 12. Open Questions & Future Considerations

### 12.1 Open Questions

1. Should the system support multi-site deployments with centralized management?
2. What's the right balance between automated response and human confirmation?
3. Should we support encrypted DNS (DoH/DoT) passthrough analysis?
4. Is there value in optional (opt-in) anonymized threat intelligence sharing?

### 12.2 Future Enhancements

- SIEM integration (Splunk, Elastic) for enterprise users
- Mobile app for alerts and basic management
- Honeypot integration for active threat detection
- VPN/WireGuard integration for remote device monitoring
- Integration with Home Assistant for smart home security

---

## Appendix A: AdGuard Home API Reference

Key endpoints used by NetGuardian AI:

```bash
# Query Log (polling)
GET /control/querylog?limit=100&offset=0

# Statistics
GET /control/stats

# Add blocked client
POST /control/clients/add
{
  "name": "quarantined-device",
  "ids": ["aa:bb:cc:dd:ee:ff"],
  "blocked_services": [],
  "upstreams": [],
  "use_global_settings": false,
  "filtering_enabled": false,
  "parental_enabled": false,
  "safesearch_enabled": false,
  "safebrowsing_enabled": false,
  "use_global_blocked_services": false,
  "blocked": true
}
```

---

## Appendix B: Sample Detection Rules

Pre-configured detection rules included with NetGuardian AI:

```json
// High-entropy DNS queries (potential DGA)
{
  "id": "dns_high_entropy",
  "conditions": {
    "all": [
      { "field": "dns.entropy_score", "operator": "gt", "value": 4.0 },
      { "field": "dns.subdomain_length", "operator": "gt", "value": 20 }
    ]
  },
  "severity": "high"
}

// Unexpected Ollama traffic
{
  "id": "ollama_unexpected",
  "conditions": {
    "all": [
      { "field": "connection.dest_port", "operator": "eq", "value": 11434 },
      { "field": "device.profile_tags", "operator": "not_contains", "value": "ai_workstation" }
    ]
  },
  "severity": "critical"
}

// New external destination
{
  "id": "new_destination",
  "conditions": {
    "all": [
      { "field": "connection.dest_ip", "operator": "is_external", "value": true },
      { "field": "connection.dest_ip", "operator": "not_in_baseline", "value": true }
    ]
  },
  "severity": "medium"
}
```

---

## Appendix C: LLM Prompt Templates

Sample prompts for threat analysis. Prompts are structured for optimal cache efficiency - static system context comes first (cacheable), followed by dynamic event-specific data.

```
# Alert Triage Prompt

# CACHEABLE SECTION (system context - place first for prompt caching)
You are a network security analyst for NetGuardian AI, a home network 
security monitoring system. Your role is to analyze security alerts 
and provide actionable assessments.

When analyzing alerts, consider:
- Device behavioral baselines and deviations
- Known threat patterns (DGA, exfiltration, lateral movement)
- LLM-malware indicators (unexpected Ollama traffic, model enumeration)
- False positive likelihood based on device type and history

Always provide your analysis as structured JSON.

# DYNAMIC SECTION (event-specific - changes per request)
Alert Details:
- Device: {device_name} ({device_mac})
- Rule Triggered: {rule_name}
- Timestamp: {timestamp}
- Raw Event Data: {event_json}

Recent device activity (last 24h):
{activity_summary}

Device baseline profile:
{baseline_summary}

Analyze this alert and provide:
1. Confidence score (0-100) that this is a genuine threat
2. Plain-language explanation of what occurred
3. Potential impact if this is malicious
4. Recommended actions
5. Any correlations with other recent events

Format your response as JSON.
```
