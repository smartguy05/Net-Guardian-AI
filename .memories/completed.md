# NetGuardian AI - Completed Tasks

Condensed summary of completed implementation work.

---

## Phase 9: Semantic Log Analysis (January 2026)

**Database**: 6 tables (LogPattern, SemanticAnalysisConfig, IrregularLog, SemanticAnalysisRun, SuggestedRule, SuggestedRuleHistory) with 4 enums - `backend/app/models/semantic_analysis.py`

**Services**:
- `pattern_normalizer.py`: Regex normalization (IPs, timestamps, UUIDs, emails, URLs, paths, hex, numbers)
- `pattern_service.py`: Pattern CRUD, UPSERT, rarity detection
- `semantic_analysis_service.py`: Real-time pattern recording, batch LLM analysis, irregularity detection
- `rule_suggestion_service.py`: Hash-based deduplication, rule approval/rejection tracking

**LLM Providers** (`backend/app/services/llm_providers/`):
- `base.py`: BaseLLMProvider ABC, LLMAnalysisResult dataclass
- `claude_provider.py`: Anthropic API with prompt caching
- `ollama_provider.py`: Local Ollama via httpx
- `factory.py`: Provider instantiation

**API**: `backend/app/api/v1/semantic.py` - Config, patterns, irregular logs, analysis runs, suggested rules endpoints

**Frontend**: SemanticReviewPage, PatternsPage, SuggestedRulesPage with expandable rows, AI research queries

**Scheduler**: `semantic_scheduler.py` for periodic batch analysis, integrated in main.py

---

## Phase 8: Landing Page & Help System

- **LandingPage.tsx**: Hero, 8 feature cards, screenshots gallery, architecture diagram, quick start
- **DocsPage.tsx**: 19 documentation sections with sticky navigation
- **Help System**: Zustand store, HelpButton, HelpPanel with `?` keyboard shortcut, context-sensitive content for 14+ pages
- **Routing**: Dashboard under `/dashboard/*`, public landing at `/`

---

## Phase 7: Technical Debt & Testing

**Prometheus Metrics**: `metrics_service.py` - HTTP counters/histograms, WebSocket gauges, event/alert/anomaly metrics

**Test Coverage**: 488 → 934 tests
- Parser tests: AdGuard, syslog, JSON, custom, NetFlow, sFlow, Loki, Authentik, endpoint
- Collector tests: API pull, file watch, UDP listener, error handler, registry
- Service tests: Baseline, anomaly, pattern, semantic analysis, LLM providers, rule suggestion
- API tests: Auth, devices, alerts, rules, users, semantic, OIDC

---

## Phase 6: Feature Enhancements

| Feature | Key Files |
|---------|-----------|
| Dark Mode | Tailwind config, theme store, all pages |
| WebSockets | JWT auth, connection manager, heartbeat, real-time alerts/devices |
| Email Notifications | SMTP service, HTML templates, notification preferences model |
| ntfy.sh Push | HTTP notifications with priority/emoji |
| 2FA (TOTP) | QR generation, backup codes, login flow |
| Data Retention | Configurable days per type, dry-run cleanup |
| CSV/PDF Export | ReportLab, events/alerts/devices/audit exports |
| Device Tagging | Bulk tagging modal, tag filtering, management endpoints |
| Custom Rules UI | Rule builder, condition groups, action config, testing |
| Mobile Responsive | Touch targets, responsive columns, safe areas |
| Threat Intel Feeds | CSV/JSON/STIX feeds, indicator lookup |
| Ollama Monitoring | Threat patterns, risk scoring, background loop |
| Collector Errors | Error categorization, retry config, circuit breaker |
| Rate Limiting | Token bucket, Redis-based, per-endpoint categories |
| CI/CD | GitHub Actions: lint, test, coverage, Docker, security scan |

---

## Phase 5: Extensions & Performance

- **Endpoint Agent**: Standalone Python agent with process/network monitoring
- **NetFlow/sFlow**: v5/v9 parsing, UDP listener, suspicious flow detection
- **Security**: Rate limiting utilities, input validation, startup checks
- **Performance**: DB pool tuning, shared HTTP client, Redis caching decorators

---

## Authentik Integration (January 2026)

**Backend**:
- Config: `backend/app/config.py` (authentik_* settings)
- User model: external_id, external_provider, is_external fields
- Migration: `20260127_0010_010_add_authentik_support.py`
- OIDC Service: `backend/app/services/oidc_service.py` (PKCE, JWKS, token validation)
- Auth endpoints: GET /oidc/config, GET /oidc/authorize, POST /oidc/callback
- Email-based account linking for pre-created local users

**Frontend**:
- Types/hooks for OIDC operations
- LoginPage SSO button with PKCE flow
- OIDCCallbackPage for callback handling

**Parser**: `backend/app/parsers/authentik_parser.py` - action severity mapping, security event detection

---

## Grafana Loki Parser

- `backend/app/parsers/loki_parser.py`: Query API and push API formats, nanosecond timestamps, severity detection
- Migration for LOKI parser type
- Events page Source column and filtering

---

## Synology NAS Syslog Support (January 2026)

- Added `udp_listen` to frontend SourceType and AddSourceModal
- Parser compatibility: syslog, netflow, sflow with udp_listen
- Migration: `20260128_0012_012_add_udp_listen_source_type.py`
- Documentation: user-guide, deployment-guide, configuration.md

---

## Collector Performance Optimizations (January 2026)

`backend/app/services/collector_service.py`:
- **Batch inserts**: BATCH_SIZE=100, BATCH_TIMEOUT=2.0s, single commit per batch
- **Concurrent processing**: MAX_CONCURRENT_BATCHES=3 via asyncio.Semaphore
- **Deferred semantic analysis**: SEMANTIC_QUEUE_SIZE=10000, background worker
- **Device cache**: DeviceCache class with DEVICE_CACHE_TTL=300s

---

## Codebase Lint Fixes (January 2026)

- Auto-fixed 1783 lint errors with ruff (UP006, UP035, UP045 deprecated typing patterns)
- Fixed 29 remaining errors manually:
  - E712: SQLAlchemy boolean comparisons (`== True` → `.is_(True)`)
  - F821: Forward references in models (added TYPE_CHECKING imports)
  - F841: Unused variables (prefixed with `_`)
  - N806: Constant naming in function (`FIELD_TYPES` → `field_types`)
  - N818: Exception naming (`NetGuardianException` → `NetGuardianError` with alias)
- Models updated: alert.py, anomaly.py, device.py, device_baseline.py, raw_event.py
- Services updated: collector_service.py, anomaly_service.py, pattern_service.py, retention_service.py, semantic_analysis_service.py, threat_intel_service.py
- Parsers updated: custom_parser.py, netflow_parser.py, sflow_parser.py
- Device creation race condition fix: `_batch_get_or_create_devices` handles concurrent batches

---

## Key Bug Fixes

- Route ordering: Static routes before dynamic `/{id}` routes in devices.py
- TestRuleModal/EditRuleModal: Legacy conditions validation and auto-conversion
- Dark theme: Modal contrast issues in AddSourceModal, EditUserModal, AddUserModal
- Test suite: Fixed 33 failing tests (parameter names, mock attributes, async patches)

---

## Documentation Updates

- `CLAUDE.md`: Test counts, LLM providers, database layer, all env variables
- `docs/architecture-guide.md`: Full system overview
- `docs/configuration.md`: 80+ env variables documented
- `docs/user-guide.md`: All features documented
- `docs/deployment-guide.md`: Docker, syslog, Authentik setup
- `README.md`: Phase 9 status, AI features, 19 UI pages, source types table

---

## Demo Data

`backend/scripts/seed_demo_data.py`:
- 3 users (admin/operator/viewer)
- 17 devices with varied types/statuses
- 6 log sources (AdGuard, nginx, syslog-nas, NetFlow, sFlow, Loki)
- 380+ events, 6 detection rules, 13 patterns, 6 irregular logs, 5 suggested rules
