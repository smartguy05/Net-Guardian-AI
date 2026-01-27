# NetGuardian AI - Completed Tasks

Tasks completed during implementation.

---

## Test Suite Improvements - API Tests (January 2026)

### Users API Tests (22 tests)
- [x] List users with pagination (empty, with data)
- [x] Create user (success, duplicate username, default role)
- [x] Get user by ID (success, not found)
- [x] Update user (email, role, deactivate, not found)
- [x] Deactivate user (success, self-deactivation rejected, not found)
- [x] Reset user password (success, not found)
- [x] Schema validation tests (UserCreate, UserUpdate, UserResponse)

### Rules API Tests (36 tests)
- [x] List rules with filters (all, by enabled, by severity)
- [x] Get condition fields (returns all fields with descriptions)
- [x] Get rule by ID (success, not found)
- [x] Create rule (success, duplicate ID)
- [x] Update rule (name, severity, not found)
- [x] Delete rule (success, not found)
- [x] Enable/disable rule (success, not found)
- [x] Test rule against sample event (matches, no match, OR logic)
- [x] Operator tests (contains, regex, gt/lt, in)
- [x] Validation tests (operators, logic, action types, rule ID format)
- [x] Response action normalization (legacy strings, dict format)

---

## Test Suite Improvements - BaselineService & AnomalyService (January 2026)

### BaselineService Tests (30 tests)
- [x] DNS/Traffic/Connection metrics calculation (empty, with events, edge cases)
- [x] Status transition tests (LEARNING, READY, STALE boundaries)
- [x] Traffic metrics edge cases (mixed protocols, many ports, high blocked ratio)
- [x] Connection metrics edge cases (all internal, all external, missing target_ip)
- [x] IP classification tests (IPv4 private classes A/B/C, loopback, invalid formats)

### AnomalyService Tests (36 tests)
- [x] Async detection method tests for no baselines and learning baselines scenarios
- [x] Severity calculation tests (high-risk vs standard anomaly types)
- [x] Volume spike detection math verification (z-score calculations)
- [x] AnomalyService facade tests (`get_device_anomalies`, `get_active_anomalies`, `update_anomaly_status`)
- [x] `run_detection_for_all_devices()` batch operation tests
- [x] Suspicious port detection tests (common safe, alternative web, service ports)
- [x] Alert creation tests for high/low severity anomalies
- [x] Z-score calculation tests (normal, threshold, above, high, critical, extreme)

### Test Quality Review (January 2026)
- [x] Sub-agent review of newly added tests for quality and usefulness
- [x] Removed TestBaselineCalculatorAsyncMethods (6 tests) - only tested mock behavior
- [x] Removed TestBaselineService (4 tests) - tested mock setup, too brittle
- [x] Removed 3 baseline structure verification tests - only tested fixtures
- [x] Fixed invalid IP test assertion (was `assert result is False or True` - always passes)

**Total: 66 passing tests** in baseline and anomaly service test files (13 low-value tests removed).

---

## Dark Theme Polish (January 2026)

### Modal and Dropdown Dark Theme Review - COMPLETE
- [x] Reviewed all 8 modal components for dark theme consistency
- [x] Fixed AddSourceModal.tsx:
  - Added `dark:bg-zinc-800` to modal container
  - Added `dark:border-zinc-700` to header/footer borders
  - Added `dark:bg-primary-900/30` to header icon background
  - Added dark text variants to all labels (`dark:text-gray-300`)
  - Added dark text to title/description (`dark:text-white`, `dark:text-gray-400`)
  - Added dark variants to source type selection buttons
  - Added dark variants to API Push info box
  - Added dark variants to error message box
  - Added dark footer background (`dark:bg-zinc-800/50`)
- [x] Fixed ThreatIntelPage.tsx:
  - Added `dark:text-gray-200` to feed action menu items
- [x] Verified other modals already had proper dark theme styling:
  - AddFeedModal, CreateRuleModal, EditRuleModal, BulkTagModal
  - EditUserModal, AddUserModal, TestRuleModal
- [x] Verified dropdowns already had proper dark theme styling:
  - ExportButton, TagFilter, UsersPage action menu

---

## Screenshot Capture for Landing Page & Help System (January 2026)

### Playwright MCP Screenshots - COMPLETE
- [x] Configured Playwright MCP browser automation
- [x] Set browser viewport to 1920x1080 for consistent screenshots
- [x] Logged in with demo_admin credentials
- [x] Captured all 9 dark mode screenshots:
  - dashboard-dark.png
  - devices-dark.png
  - alerts-dark.png
  - anomalies-dark.png
  - events-dark.png
  - topology-dark.png
  - rules-dark.png
  - chat-dark.png
  - settings-dark.png
- [x] Toggled to light theme via Settings button
- [x] Captured all 9 light mode screenshots:
  - dashboard-light.png
  - devices-light.png
  - alerts-light.png
  - anomalies-light.png
  - events-light.png
  - topology-light.png
  - rules-light.png
  - chat-light.png
  - settings-light.png
- [x] All 18 screenshots saved to `frontend/public/screenshots/`
- [x] Screenshots show realistic demo data from seeded database

---

## Help Content Accuracy Review (January 2026)

### Help System Content Update - COMPLETE
- [x] Reviewed all 19 frontend pages against helpContent.ts
- [x] Updated Dashboard help content with accurate Key Metrics, DNS Block Rate, Top Queried Domains sections
- [x] Updated Devices help content with tagging, bulk actions, export, and quarantine features
- [x] Updated Device Details help content with tabs (Events, Baselines, Anomalies)
- [x] Updated Events help content with source filtering and export functionality
- [x] Updated Alerts help content with AI Analysis section and export
- [x] Updated Anomalies help content with stats overview, filtering, and Run Detection
- [x] Updated Rules help content with Test Rules feature and rule actions
- [x] Updated Threat Intel help content with Feeds, Lookup, and Local Indicators tabs
- [x] Updated Quarantine help content with stats, integration status, recent activity, sync
- [x] Updated Chat help content with model selection (Fast/Balanced/Deep)
- [x] Updated Sources help content with API Push sources and API key display
- [x] Updated Settings help content with four tabs (General, Notifications, Security, Data Retention)
- [x] Updated Topology help content with stats, network map, controls, and node interaction
- [x] Updated Patterns help content with stats, filtering/search, pattern table, ignore/unignore
- [x] Updated Semantic Review help content with stats, filtering, irregular log table, review actions
- [x] Updated Suggested Rules help content with tabs, rule cards, approval/rejection workflows
- [x] Removed outdated keyboard shortcuts that don't exist in actual pages
- [x] All help content now matches actual page functionality

---

## CLAUDE.md Comprehensive Update (January 2026)

### Documentation Accuracy Audit - COMPLETE
- [x] Updated test count from 256 to 488 tests
- [x] Added Loki parser to parsers list
- [x] Added Database layer (app/db/) to architecture section
- [x] Added LLM Provider Architecture section with factory pattern documentation
- [x] Added llm_providers/ and integrations/ subdirectories to services description
- [x] Expanded Integration Points with file paths
- [x] Expanded Configuration section with all environment variable categories:
  - Core Settings
  - Database Pool Settings
  - LLM Configuration
  - Ollama Configuration
  - Semantic Analysis
  - Rate Limiting
  - Integrations
- [x] Expanded Important Files section with:
  - Additional core modules (security.py, validation.py, http_client.py, rate_limit.py)
  - Full list of key API endpoints (15 endpoints)
  - Key Services list (11 services)
  - Database Models list (8 models)
- [x] Added Frontend Structure section documenting:
  - Pages, Components, API, Stores, Hooks, Types directories
  - Key frontend patterns (React Query, Zustand, Tailwind, WebSocket)
- [x] Added additional test directories (api/, integration/, factories/)

---

## docs/ Folder Accuracy Review (January 2026)

### Documentation Updates - COMPLETE
- [x] Updated LLM model names in `docs/configuration.md`:
  - Changed `claude-sonnet-4-20250514` to `claude-sonnet-4-latest`
  - Changed `claude-haiku-4-20250514` to `claude-3-5-haiku-latest`
- [x] Updated LLM model names in `docs/deployment-guide.md` to match
- [x] Updated `docs/implementation-status.md`:
  - Changed phase status from "Phase 5 IN PROGRESS" to "Phase 9 COMPLETE"
  - Updated LLM model references to latest versions
  - Added Phase 6-9 feature summaries
  - Added 80+ missing API endpoints across 11 categories:
    - Detection Rules, Threat Intelligence, Semantic Analysis
    - Network Topology, Notifications, Admin
    - Metrics, Audit, Integrations, Playbooks
  - Updated test coverage table (added Loki parser, semantic analysis tests)
  - Updated total test count from 256 to 380+
- [x] Added missing Ollama config settings to `docs/configuration.md`:
  - `OLLAMA_DEFAULT_MODEL` (default: llama3.2)
  - `OLLAMA_TIMEOUT_SECONDS` (default: 120)

---

## README.md Update (January 2026)

### Documentation Accuracy Review - COMPLETE
- [x] Updated Current Status to Phase 9 (Semantic Log Analysis)
- [x] Added new AI Features section with:
  - AI Chat Assistant with model selection
  - AI Alert Analysis
  - AI Research Queries
  - AI Rule Suggestions
- [x] Added Semantic Log Analysis to Detection & Analysis section
- [x] Added In-App Documentation to Core Features
- [x] Added Phase 8 (Landing Page & Help System) to Roadmap
- [x] Added Phase 9 (Semantic Log Analysis) to Roadmap
- [x] Added UI Pages table documenting all 19 frontend pages
- [x] Added Supported Source Types section (api_pull, file_watch, api_push, udp_listen)
- [x] Added Supported Parsers table (11 parsers)
- [x] Updated Project Structure with accurate counts (25+ routers, 11 parsers, 250+ tests, 20 pages)
- [x] Updated feature list to include Grafana Loki

---

## Log Source Additions (January 2026)

### Grafana Loki Parser - COMPLETE
- [x] Created `backend/app/parsers/loki_parser.py`
  - Handles Loki query API response format (`/loki/api/v1/query_range`)
  - Handles Loki push API format (streams with values)
  - Single stream object and list of streams support
  - Nanosecond timestamp parsing to datetime
  - Severity detection from labels (`level`, `severity`, `log_level`)
  - Severity extraction from log line patterns (`[ERROR]`, `level=error`)
  - Event type mapping from job/app labels (nginx→HTTP, coredns→DNS, etc.)
  - IP address extraction from log lines (filters localhost)
  - Configurable label mappings (severity_label, event_type_label, client_ip_label)
  - Custom event type mappings via config
  - All labels preserved in parsed_fields
- [x] Added `LOKI = "loki"` to ParserType enum in `backend/app/models/log_source.py`
- [x] Registered parser in `backend/app/parsers/__init__.py`
- [x] Created `backend/tests/parsers/test_loki_parser.py` with 33 tests
  - Query API and push API format tests
  - Timestamp parsing tests
  - Severity and event type mapping tests
  - IP extraction tests
  - Configuration option tests
  - Error handling tests
- [x] Added Loki log source to demo data script (`backend/scripts/seed_demo_data.py`)
  - New log source: `loki-aggregator` (Grafana Loki Logs)
  - 10 demo Loki events (nginx, auth-service, systemd, kube-apiserver)
- [x] Updated documentation:
  - `docs/user-guide.md` - Added Grafana Loki Sources section with configuration examples
  - `docs/deployment-guide.md` - Added Loki API example, updated log source count to 7
  - `README.md` - Added Grafana Loki to multi-source log collection features
- [x] Created database migration for LOKI parser type (`backend/alembic/versions/20260123_1654_4ac0c165a6e9_add_loki_parser_type.py`)
- [x] Added Source column and filter to Events page (`frontend/src/pages/EventsPage.tsx`)
  - New "Source" column showing log source name with database icon
  - Source filter dropdown populated from useSources hook
  - Expanded event details now show Source name and ID
  - Added missing event types to filter (flow, endpoint, llm)
  - Updated eventTypeLabels to include all event types
  - Updated export functions in hooks.ts to support source_id parameter

### Semantic Review Page Expandable Rows - COMPLETE
- [x] Added expandable row functionality to SemanticReviewPage
- [x] Created `IrregularLogRow` component with expand/collapse on click
- [x] Expanded view shows:
  - Metadata row: Source name, Event ID, Pattern ID, Detection timestamp
  - Detection Reason section with full text
  - LLM Analysis section with full analysis text
  - Review Status section with review timestamp (if reviewed)
- [x] Added chevron icons (ChevronRight/ChevronDown) to indicate expandable state
- [x] Added relative timestamps ("2 hours ago") to timestamp column
- [x] Shows source names instead of raw source IDs using useSources hook
- [x] Fixed pre-existing pagination bug (added missing totalItems and pageSize props)
- [x] Removed unused searchQuery state variable

### Semantic Review Page "Research this issue" Button - COMPLETE
- [x] Added "Research this issue" button to expanded rows with AI-powered query generation
- [x] Backend: Created `/api/v1/semantic/irregular/{id}/research-query` endpoint
  - Uses Anthropic Claude API to generate high-quality search queries
  - Fetches log source details (name, parser type, description) from database
  - Sends software/source name, parser type, detection reason, LLM analysis, and severity to Claude
  - Claude generates targeted 5-10 word security research queries including the software name
  - System prompt includes examples like "AdGuard DNS blocking malicious domain detection"
  - Returns both the query and pre-built Google search URL
  - Falls back gracefully if API unavailable
- [x] Frontend: Added `useGenerateResearchQuery` hook in hooks.ts
- [x] Button shows loading spinner while generating query
- [x] Opens Google search in new tab with AI-generated query
- [x] Fallback to basic search if API call fails
- [x] Added action bar at bottom of expanded row with Research and Mark Reviewed buttons

---

## Bug Fixes (January 2026)

### TestRuleModal Legacy Conditions Fix
- [x] Fixed 422 validation error when testing rules with legacy conditions format
  - Added detection for legacy `conditions` format (flat array of condition objects)
  - Auto-converts legacy format to new structured `condition_groups` format on modal open
  - Filters out conditions with empty/whitespace `field` or `operator`
  - Trims whitespace from all string values
  - Uses nullish coalescing to ensure `value` is never undefined
  - Shows user-friendly error if no valid conditions exist after filtering

### EditRuleModal Legacy Conditions Auto-Conversion
- [x] Added auto-conversion of legacy conditions format to new structured format
  - Detects when rule has legacy `conditions` array without `condition_groups`
  - Automatically wraps legacy conditions in a single AND group on modal open
  - Ensures conditions are editable in the new UI without manual migration

### Sources Page Optimistic Updates
- [x] Added optimistic UI updates for enable/disable toggle
  - Toggle immediately reflects state change in UI
  - Rolls back on error with toast notification
  - Improves perceived responsiveness

### EditUserModal Dark Theme Fixes
- [x] Fixed poor contrast in dark mode for EditUserModal component
  - Modal background (`dark:bg-zinc-800`)
  - Form labels and input fields
  - Role dropdown and active status checkbox
  - Button hover states and focus rings
  - Error messages

### AddUserModal Dark Theme Fixes (In Progress)
- [x] Fixed poor contrast in dark mode for AddUserModal component
  - Modal background and header text
  - Form labels and input fields
  - Role selection dropdown
  - Password field styling
  - Button states (primary/secondary)

### API Route Ordering Fix
- [x] Fixed 422 error on `/api/v1/devices/quarantined` endpoint
  - Cause: Static routes (`/quarantined`, `/export/csv`, `/tags/all`, `/bulk-tag`) were defined after dynamic `/{device_id}` route
  - FastAPI matches routes in order, so "quarantined" was being parsed as a UUID
  - Reordered routes in `backend/app/api/v1/devices.py` so static routes come first

### API Data Format Fixes (earlier)
- [x] Fixed 500 error on `/api/v1/rules` - response_actions format mismatch
- [x] Fixed 500 error on `/api/v1/threat-intel/indicators` - metadata vs extra_data attribute conflict

---

## Phase 9: Semantic Log Analysis - COMPLETE (January 2026)

### Database Models - COMPLETE
- [x] Created `backend/app/models/semantic_analysis.py`
  - LogPattern model (normalized patterns, occurrence tracking, ignore flag)
  - SemanticAnalysisConfig model (per-source config, LLM provider selection)
  - IrregularLog model (flagged logs, LLM review status, severity scores)
  - SemanticAnalysisRun model (batch run audit trail)
  - SuggestedRule model (LLM-generated rule suggestions)
  - SuggestedRuleHistory model (deduplication tracking)
  - Enums: LLMProvider, AnalysisRunStatus, SuggestedRuleStatus, SuggestedRuleType
- [x] Created Alembic migration `009_add_semantic_analysis.py`
  - 6 tables: log_patterns, semantic_analysis_configs, irregular_logs, semantic_analysis_runs, suggested_rules, suggested_rule_history
  - 4 PostgreSQL enums with proper indexes

### Pattern Normalizer Service - COMPLETE
- [x] Created `backend/app/services/pattern_normalizer.py`
  - PatternNormalizer class with regex-based normalization
  - Replaces: IPs, timestamps, UUIDs, emails, URLs, paths, hex strings, numbers
  - normalize() returns (pattern, hash) tuple
  - extract_variables() for variable extraction
  - is_similar() for pattern similarity comparison

### Pattern Service - COMPLETE
- [x] Created `backend/app/services/pattern_service.py`
  - PatternService for pattern CRUD operations
  - record_pattern() with PostgreSQL UPSERT for efficiency
  - get_pattern_stats() for source statistics
  - is_pattern_rare() based on config threshold
  - mark_pattern_ignored() for user ignore toggle
  - get_patterns_for_source() with filtering

### LLM Provider Abstraction - COMPLETE
- [x] Created `backend/app/services/llm_providers/` directory
  - `base.py`: BaseLLMProvider ABC, LLMAnalysisResult dataclass, SEMANTIC_ANALYSIS_SYSTEM_PROMPT
  - `claude_provider.py`: ClaudeLLMProvider using Anthropic API with prompt caching
  - `ollama_provider.py`: OllamaLLMProvider using httpx for local Ollama
  - `factory.py`: LLMProviderFactory with get_provider() and get_available_provider()

### Semantic Analysis Service - COMPLETE
- [x] Created `backend/app/services/semantic_analysis_service.py`
  - SemanticAnalysisService orchestrating pattern learning and irregularity detection
  - process_event() for real-time pattern recording
  - run_analysis() for batch LLM analysis
  - get_irregular_logs() with filtering
  - mark_reviewed() for user review tracking
  - get_stats() for dashboard statistics

### Rule Suggestion Service - COMPLETE
- [x] Created `backend/app/services/rule_suggestion_service.py`
  - RuleSuggestionService for LLM-generated rule management
  - create_from_llm_response() with hash-based deduplication
  - approve_rule() creates actual DetectionRule when enabled
  - reject_rule() with reason tracking
  - get_pending_rules() and get_history() for UI

### API Endpoints - COMPLETE
- [x] Created `backend/app/api/v1/semantic.py`
  - Configuration: GET/PUT /semantic/config/{source_id}
  - Patterns: GET /semantic/patterns, PATCH /semantic/patterns/{id}
  - Irregular logs: GET /semantic/irregular, PATCH /semantic/irregular/{id}/review
  - Analysis runs: GET /semantic/runs, POST /semantic/runs/{source_id}/trigger
  - Stats: GET /semantic/stats, GET /semantic/stats/{source_id}
  - Suggested rules: GET /semantic/rules, POST /semantic/rules/{id}/approve, POST /semantic/rules/{id}/reject
- [x] Registered router in `backend/app/api/v1/router.py`

### Event Pipeline Integration - COMPLETE
- [x] Updated `backend/app/services/collector_service.py`
  - Added semantic analysis call in _handle_event() after commit
  - Non-blocking integration (errors logged, not thrown)

### Frontend Components - COMPLETE
- [x] Added types to `frontend/src/types/index.ts`
  - SemanticAnalysisConfig, LogPattern, IrregularLog, SemanticAnalysisRun
  - SuggestedRule, SemanticStats, and related types
- [x] Added hooks to `frontend/src/api/hooks.ts`
  - useSemanticConfigs, useSemanticConfig, useUpdateSemanticConfig
  - usePatterns, useUpdatePattern
  - useIrregularLogs, useMarkIrregularReviewed
  - useSuggestedRules, usePendingSuggestedRules, useApproveRule, useRejectRule
  - useSemanticStats, useTriggerAnalysis
- [x] Created `frontend/src/pages/SemanticReviewPage.tsx`
  - Stats cards (patterns, irregular logs, pending review, high severity)
  - Filters (source, reviewed status, severity)
  - Paginated table with LLM analysis display
  - Mark reviewed action
- [x] Created `frontend/src/pages/PatternsPage.tsx`
  - Stats summary (total patterns, irregular detected, last analysis)
  - Filters (source, ignored status, rare only, search)
  - Pattern table with occurrence counts and toggle ignore
- [x] Created `frontend/src/pages/SuggestedRulesPage.tsx`
  - Tabbed interface (Pending Review, All Rules)
  - Rule cards with status, type, reason, benefit
  - Approve (with enable toggle) and reject (with reason) actions
- [x] Added routes to `frontend/src/App.tsx`
  - /dashboard/semantic-review
  - /dashboard/patterns
  - /dashboard/suggested-rules
- [x] Added navigation to `frontend/src/components/Layout.tsx`
  - Log Patterns (Hash icon)
  - Semantic Review (Eye icon)
  - Suggested Rules (Lightbulb icon)

### Configuration + Scheduler - COMPLETE
- [x] Added settings to `backend/app/config.py`
  - semantic_analysis_enabled, semantic_default_llm_provider
  - semantic_default_rarity_threshold, semantic_default_batch_size
  - semantic_default_batch_interval_minutes, semantic_scheduler_enabled
  - ollama_default_model, ollama_timeout_seconds
- [x] Created `backend/app/services/semantic_scheduler.py`
  - SemanticAnalysisScheduler for periodic batch analysis
  - Checks configs and runs analysis based on batch_interval_minutes
  - Manual trigger support via trigger_source()
- [x] Updated `backend/app/main.py`
  - Start scheduler on application startup
  - Stop scheduler on application shutdown

### Tests - COMPLETE
- [x] Created `backend/tests/services/test_pattern_normalizer.py`
  - 35+ tests for IP, timestamp, UUID, email, URL, path, hex, number normalization
  - Tests for hash generation, complex messages, variable extraction, similarity
- [x] Created `backend/tests/services/test_pattern_service.py`
  - Tests for PatternService initialization and factory
  - Tests for PatternFilters and PatternStats dataclasses
  - Tests for is_pattern_rare logic and edge cases
- [x] Created `backend/tests/services/test_llm_providers.py`
  - Tests for LogConcern, BenignExplanation, SuggestedRuleData dataclasses
  - Tests for LLMAnalysisResult creation and from_dict/from_error parsing
  - Tests for BaseLLMProvider prompt building and JSON parsing
  - Tests for LLMProviderFactory with Claude and Ollama providers
- [x] Created `backend/tests/services/test_semantic_analysis_service.py`
  - Tests for SemanticAnalysisService initialization
  - Tests for IrregularLogFilters and SemanticStats dataclasses
  - Tests for process_event with mocked dependencies
  - Tests for run_analysis error conditions and force bypass
- [x] Created `backend/tests/services/test_rule_suggestion_service.py`
  - Tests for RuleSuggestionService initialization
  - Tests for RuleFilters and HistoryFilters dataclasses
  - Tests for compute_rule_hash consistency and deduplication
  - Tests for _map_rule_config_to_conditions for all rule types
  - Tests for approve/reject rule error handling
- [x] Created `backend/tests/api/test_semantic_api.py`
  - Tests for request schemas (PatternUpdateRequest, ApproveRuleRequest, etc.)
  - Tests for enum values (LLMProvider, SuggestedRuleStatus, SuggestedRuleType)
  - Tests for API router configuration and endpoint paths
  - Tests for HTTP method usage patterns

### Documentation Updates - COMPLETE
- [x] Updated `docs/user-guide.md`
  - Added Semantic Log Analysis section covering Log Patterns, Semantic Review, Suggested Rules pages
  - Configuration instructions for per-source settings and manual analysis triggers
- [x] Updated `docs/configuration.md`
  - Added Semantic Log Analysis section to table of contents
  - Added environment variables: SEMANTIC_ANALYSIS_ENABLED, SEMANTIC_DEFAULT_LLM_PROVIDER, etc.
  - Added per-source configuration JSON example
  - Updated complete example with semantic analysis settings
- [x] Updated `docs/deployment-guide.md`
  - Added Semantic Log Analysis configuration section under Integration Configuration
- [x] Updated `frontend/src/pages/DocsPage.tsx`
  - Added Semantic Log Analysis section to navigation (icon: Scan)
  - Added 5 subsections: Overview, Log Patterns, Semantic Review, Suggested Rules, Configuration
  - Full documentation with code examples for environment variables and API usage
  - Added Hash, Lightbulb, Scan icons for new section
- [x] Updated `frontend/src/content/helpContent.ts`
  - Added help slide-out for `/dashboard/patterns` (Log Patterns)
  - Added help slide-out for `/dashboard/semantic-review` (Semantic Review)
  - Added help slide-out for `/dashboard/suggested-rules` (Suggested Rules)
  - Each includes overview, 3 sections with tips

### Demo Data - COMPLETE
- [x] Updated `backend/scripts/seed_demo_data.py`
  - Added imports for semantic analysis models
  - Added 6 additional detection rules (failed auth, DNS tunneling, unusual ports, IoT monitoring, crypto mining, after hours)
  - Added 13 demo log patterns with varying occurrence counts (common, medium, rare)
  - Added 6 demo irregular logs with LLM analysis (different severity scores, some reviewed)
  - Added 5 demo suggested rules (pending, approved, implemented, rejected statuses)
  - Added 4 semantic analysis configs (for different sources)
  - Added 4 analysis runs (completed and failed)
  - Added seed functions: seed_semantic_analysis_configs, seed_log_patterns, seed_semantic_analysis_runs, seed_irregular_logs, seed_suggested_rules, seed_additional_detection_rules
  - Updated main() to call new seed functions and include in summary

---

## Phase 8: Landing Page & Help System - COMPLETE (January 2026)

### Comprehensive Documentation Page - COMPLETE
- [x] Created `frontend/src/pages/DocsPage.tsx`
  - Full documentation page covering all features
  - Table of contents with section navigation
  - 19 main sections with subsections:
    - Overview (intro, architecture, features)
    - Getting Started (requirements, installation, first login)
    - Dashboard
    - Device Management (inventory, details, tagging, baselines)
    - Event Monitoring
    - Alert Management (overview, lifecycle, AI analysis)
    - Anomaly Detection (types, algorithm, review)
    - Detection Rules (creating, conditions, actions)
    - Device Quarantine (overview, integrations, actions)
    - AI Assistant (chat, models, queries)
    - Network Topology
    - Threat Intelligence (feeds, indicators, lookup)
    - Log Sources (types, parsers, API push)
    - Automation Playbooks (triggers, actions, examples)
    - User Management (roles, 2FA)
    - Notifications (email, push)
    - Integrations (AdGuard, router, Ollama)
    - Configuration (env vars, retention)
    - API Reference (auth, endpoints, rate limiting)
  - Code blocks with copy functionality
  - Dark mode support throughout
  - Responsive design with sticky sidebar
- [x] Added `/docs` route to `App.tsx`
- [x] Updated landing page "View Full Documentation" link to use `/docs` internal route instead of external GitHub URL

### Landing Page - COMPLETE
- [x] Created public landing page at `/` route
- [x] Updated `App.tsx` routing:
  - Landing page at `/` (public)
  - Login redirects to `/dashboard` when authenticated
  - All dashboard routes moved under `/dashboard/*`
- [x] Updated `Layout.tsx` navigation hrefs to use `/dashboard` prefix
- [x] Created `frontend/src/pages/LandingPage.tsx`:
  - Fixed header with logo, nav links, theme toggle, login button
  - Hero section with headline, tagline, CTAs, and screenshot
  - Features grid (8 feature cards)
  - Screenshots section with theme toggle and page tabs
  - Architecture section with component cards and data flow diagram
  - Quick Start section with prerequisites and installation commands
  - Footer with links
- [x] Created `/public/screenshots/` directory with README
- [x] Added `resolvedTheme` to theme store for screenshot theme switching
- [x] Screenshots have fallback SVG placeholders when missing

### Help Panel System - COMPLETE
- [x] Created `frontend/src/stores/help.ts` Zustand store
  - `isOpen` state, `openHelp`, `closeHelp`, `toggleHelp` methods
- [x] Created `frontend/src/components/HelpButton.tsx`
  - Floating "?" button fixed to bottom-right
  - Triggers help panel toggle
- [x] Created `frontend/src/components/HelpPanel.tsx`
  - Slide-out panel from right edge
  - Semi-transparent backdrop overlay
  - Close via X button, backdrop click, or Escape key
  - Keyboard shortcut: `?` to toggle
  - Displays context-sensitive help based on current route
- [x] Created `frontend/src/content/helpContent.ts`
  - Help content for all 14 pages:
    - Dashboard, Devices, Device Detail, Events, Alerts, Anomalies
    - Rules, Threat Intel, Quarantine, Chat, Sources
    - Users, Settings, Topology
  - Each page has: title, overview, sections with tips
  - Some pages have keyboard shortcuts
  - `getHelpForPath()` function for route-based content lookup
- [x] Integrated HelpButton and HelpPanel into Layout.tsx

---

## Phase 7: Technical Debt & DevOps - COMPLETE (January 2026)

### Prometheus Metrics - COMPLETE
- [x] Added `prometheus-client>=0.19.0` to dependencies
- [x] Created `backend/app/services/metrics_service.py`
  - HTTP request counters and histograms
  - WebSocket connection gauges
  - Event processing counters
  - Alert and anomaly metrics
  - Device and collector metrics
  - Threat intelligence metrics
  - Database connection metrics
  - LLM usage metrics
  - Playbook execution metrics
- [x] Created `backend/app/api/v1/metrics.py` endpoint
- [x] Created `backend/app/core/middleware.py`
  - MetricsMiddleware for request tracking
  - RequestLoggingMiddleware for debug logging
- [x] Updated `backend/app/main.py` to add middleware
- [x] Registered metrics router

### Network Topology Visualization - COMPLETE
- [x] Created `backend/app/api/v1/topology.py`
  - GET /topology - Network topology data with nodes and links
  - GET /topology/device/{id}/connections - Device connection details
  - Device event counts and connection analysis
- [x] Registered topology router
- [x] Added TopologyNode, TopologyLink, TopologyData types to frontend
- [x] Created `frontend/src/pages/TopologyPage.tsx`
  - Canvas-based force-directed graph visualization
  - Interactive drag, pan, zoom
  - Node selection with detail panel
  - Legend for node types
  - Configurable time window
- [x] Added useTopology hook to frontend
- [x] Added /topology route and nav item

### Collector Error Handling - COMPLETE
- [x] Created `backend/app/collectors/error_handler.py`
  - ErrorCategory enum for error classification
  - CollectorError structured error class
  - categorize_error() function for automatic classification
  - RetryConfig and RetryHandler with exponential backoff
  - CircuitBreaker class (closed/half_open/open states)
  - ErrorTracker for error rate monitoring
  - @with_retry decorator for easy retry logic
- [x] Added collector error metrics (COLLECTOR_ERRORS_TOTAL, COLLECTOR_RETRIES_TOTAL, COLLECTOR_CIRCUIT_STATE)
- [x] Updated `api_pull_collector.py` to use error handling
  - Configurable retry settings in source config
  - Circuit breaker integration
  - Error tracking and metrics reporting

### API Rate Limiting - COMPLETE
- [x] Created `backend/app/core/rate_limiter.py`
  - TokenBucket class for in-memory rate limiting
  - InMemoryRateLimiter with cleanup
  - RedisRateLimiter for distributed deployments
  - RateLimitMiddleware for FastAPI
  - Per-endpoint category rate limits (auth, chat, export, admin)
  - @rate_limit decorator for custom limits
- [x] Added rate limit settings to config.py
- [x] Updated main.py to add RateLimitMiddleware

### CI/CD Pipeline - COMPLETE
- [x] Created `.github/workflows/ci.yml`
  - Backend lint (Ruff)
  - Backend type check (mypy)
  - Backend tests with PostgreSQL and Redis services
  - Coverage upload to Codecov
  - Frontend lint (ESLint)
  - Frontend build (TypeScript + Vite)
  - Docker image build
  - Security scan (Bandit, Safety)
- [x] Created `.github/workflows/release.yml`
  - Semantic versioning from tags
  - Multi-platform Docker builds (amd64, arm64)
  - GitHub Container Registry publishing
  - Automatic changelog generation
  - GitHub Release creation

### Documentation - COMPLETE
- [x] Created `docs/configuration.md`
  - Complete environment variable reference
  - Database, Redis, HTTP client settings
  - Rate limiting configuration
  - Authentication settings
  - Integration configurations (AdGuard, router, LLM)
  - Email and ntfy notification settings
  - Example configurations for dev/production
- [x] Created `CONTRIBUTING.md`
  - Code of conduct
  - Development setup instructions
  - Project structure overview
  - Coding standards (Python, TypeScript)
  - Commit message conventions
  - Testing guidelines
  - Pull request process
  - Issue guidelines

### Demo Data Seed Script - COMPLETE
- [x] Created `backend/scripts/seed_demo_data.py`
  - Comprehensive seed script for demo/testing data
  - Creates 3 demo users (admin, operator, viewer)
  - Creates 17 devices (PCs, mobiles, IoT, servers, network equipment)
  - Creates 6 log sources (AdGuard, firewall, endpoint, NetFlow, syslog, Ollama)
  - Creates 380+ events across all types (DNS, firewall, flow, endpoint, LLM)
  - Creates 6 alerts with various severities and statuses (with LLM analysis)
  - Creates 5 anomaly detections linked to devices
  - Creates 20+ device baselines (DNS and traffic)
  - Creates 5 detection rules
  - Creates 4 playbooks with executions
  - Creates 3 threat intelligence feeds with 12 indicators
  - Creates 9 audit log entries
  - Creates notification preferences for admin
  - Creates 4 data retention policies
  - Idempotent (skips existing records)
- [x] Updated README.md with demo data section
- [x] Updated docs/deployment-guide.md with demo data section

---

## Phase 6: Feature Enhancements - COMPLETE (January 2026)

### Dark Mode - COMPLETE
- [x] Updated `tailwind.config.js` with `darkMode: 'class'` configuration
- [x] Created `stores/theme.ts` Zustand store with localStorage persistence
- [x] Created `ThemeToggle.tsx` component with sun/moon/system icons
- [x] Updated `index.css` with dark mode base styles and component classes
- [x] Updated `Layout.tsx` with dark mode variants and theme toggle
- [x] Updated all pages with `dark:` Tailwind variants (Login, Dashboard, Devices, Events, Alerts)
- [x] Updated `Pagination.tsx` component with dark mode support
- [x] Fixed AnomaliesPage dark mode (tables, badges, modal, filter section)
- [x] Fixed QuarantinePage dark mode (tables, integration cards, activity log)
- [x] Fixed SourcesPage dark mode (source names, API Key box, toggle buttons)
- [x] Fixed UsersPage dark mode (roleColors, dropdown menu, badges)

### WebSockets - COMPLETE
- [x] Created `backend/app/api/v1/websocket.py` with ConnectionManager
  - JWT token verification on connection
  - Heartbeat ping/pong mechanism
  - Message broadcasting to all clients
  - Graceful disconnection handling
- [x] Updated `backend/app/events/bus.py` to broadcast alerts and device updates via WebSocket
- [x] Created `frontend/src/hooks/useWebSocket.ts` with auto-reconnection
- [x] Created `frontend/src/components/RealtimeProvider.tsx` context
  - Toast notifications for real-time events
  - Handles alert_created, device_status_changed, anomaly_detected, system_notification
- [x] Created `frontend/src/pages/SettingsPage.tsx` with tabbed settings interface

### Email Notifications - COMPLETE
- [x] Created `backend/app/services/email_service.py`
  - Async SMTP via aiosmtplib
  - HTML email templates for alerts, anomalies, quarantine
  - Connection testing
- [x] Created `backend/app/models/notification_preferences.py`
  - Per-user email/ntfy preferences
  - Severity-based notification toggles
- [x] Created `backend/app/api/v1/notifications.py` endpoints
  - GET/PUT /preferences - User preferences CRUD
  - POST /test - Send test notifications
  - GET /status - Service configuration status
- [x] Updated `backend/app/config.py` with SMTP settings
- [x] Updated `backend/app/services/playbook_engine.py` SEND_NOTIFICATION action
- [x] Added `aiosmtplib>=3.0.0` to pyproject.toml
- [x] Created database migration `005_add_notification_preferences.py`

### ntfy.sh Notifications - COMPLETE
- [x] Created `backend/app/services/ntfy_service.py`
  - HTTP-based push notifications
  - Configurable server URL (public/self-hosted)
  - Priority and emoji tag support
  - Alert, anomaly, and quarantine notification methods
- [x] Updated `backend/app/config.py` with ntfy settings
- [x] Updated notification_preferences model with ntfy fields
- [x] Updated playbook_engine to send via ntfy
- [x] Created full NotificationSettings UI in SettingsPage
  - Toggle switches for enabling/disabling
  - Email address and ntfy topic configuration
  - Severity-based notification toggles (Critical, High, Medium, Low)
  - Event-based toggles (Anomalies, Quarantine Actions)
  - Test notification buttons
- [x] Added notification hooks to frontend API hooks

### Two-Factor Authentication (TOTP) - COMPLETE
- [x] Added `pyotp>=2.9.0`, `qrcode>=7.4`, `pillow>=10.0` to pyproject.toml
- [x] Created `backend/app/services/totp_service.py`
  - TOTP secret generation (pyotp)
  - QR code generation for authenticator apps
  - TOTP verification with valid_window
  - Backup code generation and verification
- [x] Updated `backend/app/models/user.py` with 2FA fields
  - totp_enabled (boolean)
  - totp_secret (string)
  - backup_codes (array)
- [x] Updated `backend/app/core/security.py` with `create_2fa_pending_token()`
- [x] Updated `backend/app/api/v1/auth.py` with 2FA endpoints
  - Modified login to return requires_2fa and pending_token
  - POST /2fa/verify - Complete 2FA login
  - POST /2fa/setup - Generate QR code and secret
  - POST /2fa/enable - Enable 2FA after verification
  - POST /2fa/disable - Disable 2FA (requires password)
  - POST /2fa/backup-codes - Regenerate backup codes
  - GET /2fa/status - Get 2FA status
- [x] Created database migration `006_add_2fa_fields.py`
- [x] Updated `frontend/src/stores/auth.ts` with 2FA pending state
- [x] Added 2FA hooks to `frontend/src/api/hooks.ts`
  - useVerify2FA, use2FAStatus, useSetup2FA
  - useEnable2FA, useDisable2FA, useRegenerate2FABackupCodes
- [x] Updated `frontend/src/types/index.ts` with 2FA types
- [x] Updated `frontend/src/pages/LoginPage.tsx` with 2FA verification flow
- [x] Updated SecuritySettings in SettingsPage with full 2FA management UI
  - QR code display for setup
  - Verification code input
  - Backup codes display with copy/download
  - Enable/disable controls
  - Backup code regeneration

### Data Retention Policies - COMPLETE
- [x] Created `backend/app/models/retention_policy.py`
  - RetentionPolicy model with table_name, display_name, description
  - Configurable retention_days (0 = keep forever)
  - Enabled flag, last_run timestamp, deleted_count tracking
- [x] Created `backend/app/services/retention_service.py`
  - Default policies for raw_events (30d), alerts (90d), anomaly_detections (90d)
  - Default policies for audit_logs (365d), device_baselines (forever), playbook_executions (90d)
  - Policy CRUD operations
  - Cleanup with dry_run support
  - Storage statistics per table
- [x] Created `backend/app/api/v1/admin.py` (admin-only endpoints)
  - GET /admin/retention/policies - List all policies
  - GET /admin/retention/policies/{id} - Get specific policy
  - PATCH /admin/retention/policies/{id} - Update policy (days, enabled)
  - POST /admin/retention/cleanup - Run cleanup (with dry_run option)
  - GET /admin/retention/stats - Storage statistics
- [x] Registered admin router in `backend/app/api/v1/router.py`
- [x] Created database migration `007_add_retention_policies.py`
- [x] Added retention hooks to `frontend/src/api/hooks.ts`
  - useRetentionPolicies, useRetentionPolicy
  - useUpdateRetentionPolicy, useRunRetentionCleanup
  - useStorageStats
- [x] Updated RetentionSettings component in SettingsPage
  - Storage overview with row counts and table sizes
  - Policy management table with inline editing
  - Enable/disable toggles for each policy
  - Preview cleanup (dry run)
  - Run cleanup with confirmation dialog
  - Detailed cleanup results display

### CSV/PDF Export - COMPLETE
- [x] Added `reportlab>=4.0` to pyproject.toml
- [x] Created `backend/app/services/export_service.py`
  - ExportService class with to_csv() and to_pdf() methods
  - Pre-defined column configurations for events, alerts, devices, audit
  - PDF generation with reportlab (tables, styling, headers)
  - CSV generation with proper escaping
- [x] Added export endpoints to `backend/app/api/v1/events.py`
  - GET /events/export/csv - Export events to CSV
  - GET /events/export/pdf - Export events to PDF
  - Supports filtering by event_type, severity, device_id, date range
- [x] Added export endpoints to `backend/app/api/v1/alerts.py`
  - GET /alerts/export/csv - Export alerts to CSV
  - GET /alerts/export/pdf - Export alerts to PDF
  - Supports filtering by status, severity, device_id
- [x] Added export endpoints to `backend/app/api/v1/devices.py`
  - GET /devices/export/csv - Export devices to CSV
  - GET /devices/export/pdf - Export devices to PDF
  - Supports filtering by status, device_type
- [x] Added export endpoints to `backend/app/api/v1/audit.py`
  - GET /audit/export/csv - Export audit logs to CSV (admin only)
  - GET /audit/export/pdf - Export audit logs to PDF (admin only)
  - Supports filtering by action, target_type, user_id
- [x] Created `frontend/src/components/ExportButton.tsx`
  - Dropdown button with CSV and PDF options
  - Loading state during export
  - Handles blob download
- [x] Added export functions to `frontend/src/api/hooks.ts`
  - exportEventsCSV, exportEventsPDF
  - exportAlertsCSV, exportAlertsPDF
  - exportDevicesCSV, exportDevicesPDF
  - exportAuditCSV, exportAuditPDF
- [x] Updated EventsPage with ExportButton
- [x] Updated AlertsPage with ExportButton
- [x] Updated DevicesPage with ExportButton

### Device Grouping/Tagging UI - COMPLETE
- [x] Added tag management endpoints to `backend/app/api/v1/devices.py`
  - GET /devices/tags/all - Get all unique tags with counts
  - POST /devices/bulk-tag - Add/remove tags from multiple devices
  - PUT /devices/{id}/tags - Set device tags
  - POST /devices/{id}/tags - Add single tag to device
  - DELETE /devices/{id}/tags/{tag} - Remove single tag from device
- [x] Added tags filtering to list_devices endpoint (comma-separated tags query param)
- [x] Created `frontend/src/components/TagFilter.tsx`
  - Multi-select dropdown for tag filtering
  - Checkbox-style selection with tag counts
  - Selected tags displayed as chips with clear all
- [x] Created `frontend/src/components/BulkTagModal.tsx`
  - Modal for bulk tagging selected devices
  - Create new tags on the fly
  - Add/remove tags with visual indicators
  - Existing tags list with add/remove buttons
- [x] Added tag hooks to `frontend/src/api/hooks.ts`
  - useAllTags - Fetch all tags with counts
  - useBulkTagDevices - Bulk tag mutation
  - useSetDeviceTags, useAddDeviceTag, useRemoveDeviceTag
- [x] Updated `frontend/src/pages/DevicesPage.tsx`
  - Tag filter in filters section
  - Bulk selection with checkbox column
  - Select all/deselect all toggle
  - Bulk actions bar with device count
  - Bulk tag modal integration

### Custom Detection Rules UI - COMPLETE
- [x] Created `backend/app/api/v1/rules.py`
  - GET /rules - List rules with filtering (enabled, severity, search)
  - GET /rules/fields - Get available condition fields with descriptions
  - GET /rules/{id} - Get specific rule
  - POST /rules - Create rule (admin only)
  - PATCH /rules/{id} - Update rule (admin only)
  - DELETE /rules/{id} - Delete rule (admin only)
  - POST /rules/{id}/enable - Enable rule (admin only)
  - POST /rules/{id}/disable - Disable rule (admin only)
  - POST /rules/test - Test rule conditions against sample event
- [x] Registered rules router in `backend/app/api/v1/router.py`
- [x] Added rule types to `frontend/src/types/index.ts`
  - RuleCondition, RuleConditionGroup, RuleAction
  - DetectionRule, DetectionRuleListResponse
  - CreateRuleRequest, UpdateRuleRequest
  - ConditionFieldInfo, TestRuleRequest, TestRuleResponse
- [x] Added rule hooks to `frontend/src/api/hooks.ts`
  - useRules, useRule, useRuleFields
  - useCreateRule, useUpdateRule, useDeleteRule
  - useEnableRule, useDisableRule, useTestRule
- [x] Created `frontend/src/pages/RulesPage.tsx`
  - Rule cards with expandable details
  - Conditions and actions display
  - Enable/disable toggle
  - Edit and delete actions
  - Filtering by status and severity
  - Pagination
- [x] Created `frontend/src/components/CreateRuleModal.tsx`
  - 3-step wizard (basic info, conditions, actions)
  - Visual condition builder with field selection
  - Multiple operators (eq, ne, gt, lt, contains, regex, etc.)
  - Action configuration (create_alert, quarantine, tag, webhook, etc.)
- [x] Created `frontend/src/components/EditRuleModal.tsx`
  - Edit all rule properties
  - Add/remove conditions and actions
- [x] Created `frontend/src/components/TestRuleModal.tsx`
  - Test rule against sample events
  - Sample event presets (DNS, firewall, auth)
  - JSON event editor
  - Visual condition result display
- [x] Added /rules route to `frontend/src/App.tsx`
- [x] Added Rules nav item to `frontend/src/components/Layout.tsx`

### Mobile-Responsive Improvements - COMPLETE
- [x] Added mobile-first utilities to `frontend/src/index.css`
  - .touch-target - Min 44px touch target size
  - .mobile-card, .mobile-card-row - Card view components for mobile
  - .mobile-tabs, .mobile-tab - Horizontal scrolling tabs
  - .scrollbar-hide - Hide scrollbars for mobile scroll containers
  - .btn-mobile - Mobile-friendly button with touch-manipulation
  - .safe-bottom, .safe-top - Safe area insets for notched devices
- [x] Layout already had sticky header and mobile menu
- [x] Updated `frontend/src/pages/DevicesPage.tsx`
  - Responsive column visibility (hidden md:table-cell, etc.)
  - Show IP address inline on mobile when column hidden
  - Smaller icons and padding on mobile
  - Truncate long text on mobile
- [x] Updated `frontend/src/pages/EventsPage.tsx`
  - Responsive column visibility
  - Show severity inline with type on mobile
  - Truncate domain on mobile
- [x] Dashboard and Alerts already had responsive grids

### Threat Intelligence Feed Integration - COMPLETE
- [x] Created `backend/app/models/threat_intel.py`
  - ThreatIntelFeed model (id, name, description, feed_type, url, enabled, etc.)
  - ThreatIndicator model (id, feed_id, indicator_type, value, confidence, severity, etc.)
  - FeedType enum (CSV, JSON, STIX, URL_LIST, IP_LIST)
  - IndicatorType enum (IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL, CIDR)
- [x] Created `backend/app/services/threat_intel_service.py`
  - Feed CRUD operations (create, get, update, delete)
  - Feed fetching with authentication support (none, basic, bearer, api_key)
  - Parsers for IP lists, URL lists, CSV, JSON formats
  - Indicator search and lookup with hit tracking
  - Statistics aggregation
- [x] Created `backend/app/api/v1/threat_intel.py`
  - GET /threat-intel/feeds - List feeds with filtering
  - GET /threat-intel/feeds/{id} - Get specific feed
  - POST /threat-intel/feeds - Create feed (admin only)
  - PATCH /threat-intel/feeds/{id} - Update feed (admin only)
  - DELETE /threat-intel/feeds/{id} - Delete feed (admin only)
  - POST /threat-intel/feeds/{id}/fetch - Trigger feed fetch
  - POST /threat-intel/feeds/{id}/enable - Enable feed
  - POST /threat-intel/feeds/{id}/disable - Disable feed
  - GET /threat-intel/indicators - List indicators with filtering
  - POST /threat-intel/check - Check value against indicators
  - GET /threat-intel/stats - Threat intel statistics
- [x] Registered threat_intel router in `backend/app/api/v1/router.py`
- [x] Created database migration `008_add_threat_intel.py`
  - threat_intel_feeds table
  - threat_indicators table with indexes
  - feedtype and indicatortype PostgreSQL enums
- [x] Added threat intel types to `frontend/src/types/index.ts`
  - ThreatIntelFeed, ThreatIndicator interfaces
  - FeedType, IndicatorType types
  - Request/response types for API
- [x] Added threat intel hooks to `frontend/src/api/hooks.ts`
  - useThreatFeeds, useThreatFeed
  - useCreateThreatFeed, useUpdateThreatFeed, useDeleteThreatFeed
  - useFetchThreatFeed, useEnableThreatFeed, useDisableThreatFeed
  - useThreatIndicators, useCheckIndicator
  - useThreatIntelStats
- [x] Created `frontend/src/pages/ThreatIntelPage.tsx`
  - Stats overview (total feeds, enabled feeds, indicators, hits)
  - Tabbed interface (Feeds, Indicators, Lookup)
  - Feed cards with status, indicator count, last fetch info
  - Feed management menu (fetch, enable/disable, delete)
  - Indicator table with filtering (type, severity, search)
  - Indicator lookup with results display
  - Pagination for indicators
- [x] Created `frontend/src/components/AddFeedModal.tsx`
  - 3-step wizard (basic info, feed config, authentication)
  - Feed type selection (IP list, URL list, CSV, JSON, STIX)
  - URL and update interval configuration
  - CSV field mapping for custom feeds
  - Authentication options (none, basic, bearer, api_key)
- [x] Added /threat-intel route to `frontend/src/App.tsx`
- [x] Added Threat Intel nav item to `frontend/src/components/Layout.tsx`

---

## Phase 5: Polish & Extensions - COMPLETE (January 2026)

### Ollama LLM Monitoring - COMPLETE
- [x] Added Ollama configuration settings to `config.py`
- [x] Added `LLM` event type to `EventType` enum
- [x] Added `OLLAMA` parser type to `ParserType` enum
- [x] Created `OllamaParser` with threat detection patterns
  - 40+ patterns for injection, jailbreak, exfiltration detection
  - Risk scoring (0-100) with severity mapping
  - Pattern-based and length-based detection
- [x] Created `OllamaMonitoringService`
  - Connection testing and polling
  - Threat detection and caching
  - Optional Claude-based deep analysis
  - Background monitoring loop
- [x] Created REST API endpoints (`/api/v1/ollama/*`)
  - GET `/status` - Monitoring status
  - POST `/test-connection` - Test Ollama connection (admin)
  - POST `/check` - Manual check trigger
  - POST `/analyze-prompt` - Analyze prompt for threats
  - POST `/process-request` - Process intercepted requests
  - GET `/threats` - Recent detected threats
  - POST `/start` - Start monitoring (admin)
  - POST `/stop` - Stop monitoring (admin)
- [x] Created 53 tests for parser and service

### Documentation - COMPLETE
- [x] Created `docs/deployment-guide.md` - comprehensive deployment documentation
  - Development setup instructions
  - Environment configuration reference
  - Production deployment checklist
  - Database management (migrations, backup)
  - Log source configuration
  - Monitoring and troubleshooting
  - Scaling considerations
- [x] Created `docs/user-guide.md` - user documentation
  - Getting started guide
  - Feature explanations (devices, events, alerts, anomalies)
  - AI chat usage
  - Playbook configuration
  - Best practices
  - Troubleshooting guide

### Security Hardening - COMPLETE
- [x] Created `core/rate_limit.py` - rate limiting utilities
  - `RateLimiter` class with configurable windows and blocks
  - Pre-configured limiters for login, API, and ingestion
  - Client identification via X-Forwarded-For or direct IP
- [x] Created `core/validation.py` - input validation utilities
  - `validate_password_strength()` - comprehensive password checking
  - `validate_username()` - username format validation
  - `validate_ip_address()` - IP address validation
  - `validate_domain()` - domain name validation
  - `validate_mac_address()` - MAC address validation
  - `sanitize_string()` and `sanitize_log_message()` - input sanitization
- [x] Updated `api/v1/auth.py` with security enhancements
  - Added rate limiting to login endpoint (5 attempts/min)
  - Added password strength validation to password change
  - Rate limit reset on successful login
- [x] Updated `services/init_service.py` with startup security checks
  - Warns about default/weak secret key
  - Warns about debug mode in production
  - Warns about wildcard CORS configuration
  - Warns about weak database passwords
  - Warns about long JWT expiration times
  - Warns about missing API keys
- [x] All 223 tests still passing

### Performance Optimization - COMPLETE
- [x] Added configurable database connection pool settings to `config.py`
  - `db_pool_size` (default: 20)
  - `db_max_overflow` (default: 30)
  - `db_pool_timeout` (default: 30s)
  - `db_pool_recycle` (default: 1800s)
- [x] Updated `db/session.py` to use configurable pool settings
- [x] Created `core/http_client.py` - shared HTTP client pool
  - `HttpClientPool` class for managing persistent connections
  - Configurable connection limits and keepalive
  - Global pool instance with lifecycle management
- [x] Created `core/cache.py` - Redis-based caching layer
  - `CacheService` with TTL-based caching
  - Support for pattern-based cache invalidation
  - `@cached` decorator for function result caching
- [x] Updated `main.py` to initialize cache service and cleanup HTTP pool
- [x] Updated `AdGuardHomeService` to use shared HTTP client pool
- [x] Added HTTP client configuration settings
  - `http_timeout_seconds` (default: 30)
  - `http_max_connections` (default: 100)
  - `http_keepalive_expiry` (default: 30s)
- [x] Added Redis connection pool setting
  - `redis_max_connections` (default: 50)
- [x] All 223 tests still passing

### Phase 4 Test Fixes - COMPLETE
- [x] Added missing `ActionType` values (BLOCK, UNBLOCK, TEST, SYNC, STATUS) to base enum
- [x] Updated `AdGuardHomeService.test_connection()` to return `ActionType.TEST`
- [x] Fixed `PlaybookEngine._action_log_event()` to use explicit logger methods instead of `logger.log()`
- [x] Fixed `AuditService.log_integration_action()` to include `integration_type` in details
- [x] Added `AuditService.log_user_login()` method for tracking login attempts
- [x] Updated integration tests to use correct `ActionType.BLOCK_DEVICE` values
- [x] All 223 tests passing

### Endpoint Agent - COMPLETE
- [x] Created standalone endpoint agent (`agent/netguardian_agent.py`)
  - Cross-platform Python script (Windows, Linux, macOS)
  - Process monitoring (new process detection, suspicious activity)
  - Network connection monitoring (TCP/UDP, listening ports)
  - Optional file access monitoring for sensitive paths
  - Automatic machine ID generation for unique agent identification
  - Configurable polling interval and batch sizes
  - Process whitelist support
  - SSL certificate verification toggle
  - systemd and Windows service support documentation
- [x] Created configuration template (`agent/agent_config.yaml.example`)
- [x] Created `requirements.txt` for agent dependencies (psutil, httpx, pyyaml)
- [x] Created comprehensive agent documentation (`agent/README.md`)
- [x] Created `EndpointParser` for parsing endpoint agent data
  - Parses process, network, file, auth, and system events
  - Suspicious activity detection (malicious processes, ports, file access)
  - Risk-based severity assignment
- [x] Added `EventType.ENDPOINT` to event type enum
- [x] Added `ParserType.ENDPOINT` to parser type enum
- [x] Created 11 tests for endpoint parser

### NetFlow/sFlow Integration - COMPLETE
- [x] Created `NetFlowParser` (`app/parsers/netflow_parser.py`)
  - Full NetFlow v5 binary packet parsing
  - NetFlow v9 template-based parsing support
  - JSON input support for pre-parsed data
  - Protocol number to name mapping
  - Suspicious flow detection (ports, data transfer size, scan patterns)
  - Configurable minimum thresholds (bytes, packets)
- [x] Created `SFlowParser` (`app/parsers/sflow_parser.py`)
  - sFlow v5 datagram parsing
  - Flow sample parsing with raw packet headers
  - Counter sample support (optional)
  - Ethernet, IPv4, IPv6, TCP, UDP header parsing
  - JSON input support for pre-parsed data
- [x] Created `UDPListenerCollector` (`app/collectors/udp_listener_collector.py`)
  - Async UDP server for receiving flow data
  - Configurable host, port, and queue size
  - Source IP filtering support
  - Non-blocking event processing
- [x] Added `EventType.FLOW` to event type enum
- [x] Added `SourceType.UDP_LISTEN` to source type enum
- [x] Added `ParserType.NETFLOW` and `ParserType.SFLOW` to parser type enum
- [x] Updated collector and parser registries
- [x] Created 11 tests for NetFlow parser
- [x] Created 11 tests for sFlow parser
- [x] All 256 tests passing

---

## Phase 4: Active Response - COMPLETE (January 2026)

### Integration Services
- [x] Created integration base classes (`IntegrationService`, `IntegrationResult`)
- [x] Implemented `AdGuardHomeService` for DNS-level device blocking
- [x] Implemented `UniFiService` for UniFi Controller device blocking
- [x] Implemented `PfSenseService` for pfSense/OPNsense firewall blocking
- [x] Added configuration settings for AdGuard and router integrations

### Audit System
- [x] Created `AuditLog` model with 27 action types
- [x] Created `AuditService` with logging methods for all action types
- [x] Implemented device quarantine/release audit logging
- [x] Implemented integration action audit logging
- [x] Implemented user login/action audit logging
- [x] Created database migration for audit_logs table

### Playbook Engine
- [x] Created `Playbook` model with triggers and actions
- [x] Created `PlaybookExecution` model for tracking executions
- [x] Implemented `PlaybookEngine` with trigger evaluation
- [x] Implemented playbook actions: quarantine_device, release_device, create_alert, tag_device, send_notification, execute_webhook, log_event
- [x] Added rate limiting with cooldowns and hourly execution limits
- [x] Created database migration for playbooks tables

### Quarantine Service
- [x] Created `QuarantineService` to orchestrate device isolation
- [x] Integrated with AdGuard Home blocking
- [x] Integrated with router blocking (UniFi, pfSense)
- [x] Implemented quarantine sync functionality
- [x] Added quarantined devices listing endpoint

### API Endpoints
- [x] `GET /api/v1/audit` - List audit logs (admin)
- [x] `GET /api/v1/audit/device/{id}` - Device audit history
- [x] `GET /api/v1/audit/quarantine-history` - Recent quarantine actions
- [x] `GET /api/v1/audit/stats` - Audit statistics (24h)
- [x] `GET /api/v1/integrations/status` - Integration status
- [x] `POST /api/v1/integrations/adguard/test` - Test AdGuard connection
- [x] `POST /api/v1/integrations/router/test` - Test router connection
- [x] `GET /api/v1/integrations/adguard/blocked` - AdGuard blocked list
- [x] `GET /api/v1/integrations/router/blocked` - Router blocked list
- [x] `POST /api/v1/integrations/sync-quarantine` - Sync quarantine state
- [x] `GET /api/v1/devices/quarantined` - List quarantined devices
- [x] `GET /api/v1/playbooks` - List playbooks
- [x] `POST /api/v1/playbooks` - Create playbook
- [x] `GET /api/v1/playbooks/{id}` - Get playbook
- [x] `PATCH /api/v1/playbooks/{id}` - Update playbook
- [x] `DELETE /api/v1/playbooks/{id}` - Delete playbook
- [x] `POST /api/v1/playbooks/{id}/execute` - Execute playbook manually
- [x] `POST /api/v1/playbooks/{id}/activate` - Activate playbook
- [x] `POST /api/v1/playbooks/{id}/deactivate` - Deactivate playbook
- [x] `GET /api/v1/playbooks/{id}/executions` - List playbook executions
- [x] `GET /api/v1/playbooks/actions/types` - List action types
- [x] `GET /api/v1/playbooks/triggers/types` - List trigger types

### Frontend
- [x] Created `QuarantinePage.tsx` with device management
- [x] Added integration status cards
- [x] Added quarantine activity log
- [x] Added sync quarantine functionality
- [x] Added API hooks for integrations, audit, and quarantine
- [x] Updated sidebar navigation with Quarantine link

### Tests
- [x] Created `test_phase4_integrations.py` - Integration service tests
- [x] Created `test_phase4_audit.py` - Audit service tests
- [x] Created `test_phase4_playbooks.py` - Playbook engine tests

---

## Phase 3: LLM Integration - COMPLETE (January 2026)

### LLM Service
- [x] Created `llm_service.py` with Claude API integration
- [x] Implemented prompt caching for cost optimization
- [x] Added three model tiers: Fast (Haiku), Default (Sonnet), Deep (Sonnet)
- [x] Implemented `analyze_alert()` with device/baseline context
- [x] Implemented `query_network()` for natural language queries
- [x] Implemented `summarize_incident()` for incident reports
- [x] Implemented `stream_chat()` async generator for streaming

### API Endpoints
- [x] `GET /api/v1/chat/status` - LLM service status
- [x] `POST /api/v1/chat/query` - Natural language queries
- [x] `POST /api/v1/chat/chat` - Chat with streaming support
- [x] `POST /api/v1/chat/summarize-incident` - Incident summarization
- [x] Updated `POST /api/v1/alerts/{id}/analyze` with full LLM analysis

### Frontend
- [x] Created ChatPage component with message history
- [x] Added model selector (Fast/Balanced/Deep)
- [x] Added suggested queries for quick start
- [x] Added LLM not configured warning
- [x] Added "AI Chat" navigation link

### Configuration
- [x] Added `anthropic_api_key` setting
- [x] Added `llm_model_default`, `llm_model_fast`, `llm_model_deep` settings
- [x] Added `llm_enabled`, `llm_cache_enabled` feature toggles
- [x] Added `anthropic>=0.40.0` to dependencies

### Tests
- [x] 22 tests for LLM service covering:
  - Service initialization (enabled/disabled states)
  - Model selection
  - Prompt building (with device, baseline, events context)
  - Response parsing (JSON extraction, fallback handling)
  - Disabled state error handling

---

## Phase 2: Anomaly Detection - COMPLETE (January 2026)

### Database Models
- [x] Created `DeviceBaseline` model with baseline_type, metrics, status
- [x] Created `AnomalyDetection` model with anomaly_type, severity scoring
- [x] Created migration `002_add_baselines_anomalies.py`

### Services
- [x] Created `BaselineService` with `BaselineCalculator`
  - DNS baseline (query counts, unique domains, blocked ratio)
  - Traffic baseline (connections, ports, bytes)
  - Connection baseline (destinations, protocols)
- [x] Created `AnomalyService` with `AnomalyDetector`
  - New domain detection
  - Volume spike detection (z-score)
  - Blocked ratio spike detection
  - New connection/port detection
  - Pattern change detection

### API Endpoints
- [x] `GET /api/v1/baselines` - List baselines with filtering
- [x] `GET /api/v1/baselines/device/{id}` - Device baselines
- [x] `GET /api/v1/baselines/stats/summary` - Baseline statistics
- [x] `POST /api/v1/baselines/device/{id}/recalculate` - Recalculate baseline
- [x] `POST /api/v1/baselines/recalculate-all` - Bulk recalculation
- [x] `GET /api/v1/anomalies` - List anomalies
- [x] `GET /api/v1/anomalies/active` - Active anomalies
- [x] `GET /api/v1/anomalies/device/{id}` - Device anomalies
- [x] `GET /api/v1/anomalies/stats/summary` - Anomaly statistics
- [x] `POST /api/v1/anomalies/device/{id}/detect` - Run detection
- [x] `POST /api/v1/anomalies/detect-all` - Bulk detection
- [x] `PATCH /api/v1/anomalies/{id}` - Update status

### Frontend
- [x] Created `AnomaliesPage.tsx` with filtering and status management
- [x] Updated `DeviceDetailPage.tsx` with Baselines and Anomalies tabs
- [x] Added baseline recalculation button
- [x] Added anomaly detection trigger
- [x] Added types and hooks for baselines/anomalies

### Tests
- [x] 14 tests for `BaselineService`
- [x] 16 tests for `AnomalyService`

---

## Phase 1: Foundation - COMPLETE

---

## Project Setup

- [x] Created project directory structure
- [x] Initialized git repository with `.gitignore`
- [x] Created `docker-compose.yml` with all services
- [x] Created `.env.example` and `.env` configuration files
- [x] Set up TimescaleDB container with health checks
- [x] Set up Redis container with persistence
- [x] Configured container networking

## Backend Foundation

- [x] Initialized Python project with `pyproject.toml` (hatchling build)
- [x] Created FastAPI application with lifespan management
- [x] Set up structured logging with structlog
- [x] Created health check endpoint (`/health`)
- [x] Configured CORS middleware
- [x] Created custom exception handlers

## Database Layer

- [x] Created SQLAlchemy async engine and session factory
- [x] Created base model with timestamp mixin
- [x] Created User model with bcrypt password hashing
- [x] Created Device model with status enum
- [x] Created LogSource model with config JSON fields
- [x] Created RawEvent model for normalized events
- [x] Created Alert model with status tracking
- [x] Created DetectionRule model
- [x] Set up Alembic for migrations
- [x] Created initial migration with TimescaleDB hypertable
- [x] Created PostgreSQL enums for all enum fields

## Authentication System

- [x] Implemented bcrypt password hashing (direct, not passlib)
- [x] Implemented JWT access token generation
- [x] Implemented JWT refresh token generation
- [x] Created token decode/validation function
- [x] Created `get_current_user` dependency
- [x] Created role-based permission checks (`require_admin`, `require_operator`)
- [x] Implemented login endpoint with form data
- [x] Implemented logout endpoint
- [x] Implemented token refresh endpoint
- [x] Implemented `/auth/me` endpoint
- [x] Implemented password change endpoint
- [x] Created initial admin user on first startup
- [x] Login response includes user object with role

## REST API Endpoints

- [x] Auth routes (`/api/v1/auth/*`)
- [x] Device routes (`/api/v1/devices/*`)
- [x] Event routes (`/api/v1/events/*`)
- [x] Alert routes (`/api/v1/alerts/*`)
- [x] Source routes (`/api/v1/sources/*`)
- [x] Stats routes (`/api/v1/stats/*`)
- [x] Users routes (`/api/v1/users/*`) - Admin only

## Event Bus

- [x] Created EventBus class using Redis Streams
- [x] Implemented publish methods (raw events, alerts, device updates)
- [x] Implemented consumer group creation
- [x] Implemented consumer with message acknowledgment
- [x] Created background task management for consumers
- [x] Created global event bus singleton with connect/disconnect

## Collector Framework

- [x] Created abstract BaseCollector class
- [x] Created APIPullCollector with configurable auth
- [x] Created FileCollector with watchdog integration
- [x] Created collector registry with auto-registration
- [x] Created abstract BaseParser class
- [x] Created AdGuardParser
- [x] Created JSONParser with field mapping
- [x] Created SyslogParser
- [x] Created CustomParser with regex support
- [x] **Created collector worker module** (`app/collectors/worker.py`)
  - Loads enabled sources from database
  - Creates collectors for each source type
  - Processes events and stores in TimescaleDB
  - Publishes events to Redis event bus
  - Implements device auto-discovery from IPs
- [x] Updated `__init__.py` files to auto-register collectors and parsers

## Frontend Setup

- [x] Initialized Vite + React + TypeScript project
- [x] Configured Tailwind CSS with custom colors
- [x] Set up React Query for data fetching
- [x] Set up Zustand for auth state management
- [x] Created API client with axios
- [x] Created TypeScript type definitions
- [x] Created custom hooks for all API endpoints

## Frontend Pages

- [x] Login page with JWT handling
- [x] Dashboard layout with sidebar navigation
- [x] Dashboard page with stats overview
- [x] Devices page with list and status badges
- [x] Events page with filtering
- [x] Alerts page with status management
- [x] Sources page with enable/disable toggle
- [x] Users page with full CRUD (admin-only)

## Frontend Components

- [x] StatsCard component
- [x] DeviceCard component
- [x] EventRow component
- [x] AlertCard component
- [x] SourceCard component
- [x] Loading skeletons
- [x] **AddSourceModal component** - Multi-step form for creating log sources
  - Step 1: Basic info (ID, name, description, source type, parser type)
  - Step 2: Configuration (dynamic fields based on source type)
  - Supports API Pull, File Watch, and API Push source types
  - Auth type selection (none, basic, bearer, API key)
  - Wired to POST `/api/v1/sources` endpoint
- [x] **User Management UI** - Full admin user management
  - UsersPage with user list, role badges, action menus
  - AddUserModal with username, email, role selection
  - EditUserModal with email, role, active status
  - Password reset and deactivate actions
  - Admin-only navigation filtering
  - Role-based icons (Shield=admin, UserCog=operator, Eye=viewer)

## Docker/Podman Setup

- [x] Backend Dockerfile (multi-stage build)
- [x] Frontend Dockerfile (build + nginx)
- [x] Nginx configuration with API proxy
- [x] Docker Compose with all services
- [x] Volume configuration for data persistence
- [x] Health checks for all services

---

## Bug Fixes Applied

- [x] Fixed hatchling build (added README.md, configured packages)
- [x] Fixed npm install in Dockerfile (was using npm ci without lock file)
- [x] Fixed Tailwind CSS color scales (added full 50-900 scales)
- [x] Removed unused TypeScript imports
- [x] Fixed structlog configuration for PrintLoggerFactory
- [x] Fixed SQLAlchemy `text()` wrapper for raw SQL
- [x] Fixed Redis URL settings case (lowercase)
- [x] Replaced passlib with direct bcrypt usage
- [x] Fixed SQLAlchemy enum to use values instead of names (all model files)
  - user.py, device.py, log_source.py, alert.py, raw_event.py, detection_rule.py
- [x] Fixed login response to include user object
- [x] Fixed collector/parser registration by updating `__init__.py` imports
- [x] Fixed frontend login to use URLSearchParams instead of FormData (FormData sends multipart, but OAuth2 expects x-www-form-urlencoded)
- [x] Fixed FastAPI route ordering in `semantic.py` - moved `/rules/history` endpoint before `/rules/{rule_id}` to prevent "history" being matched as a UUID parameter
- [x] Fixed `/api/v1/rules` 500 error - Added `_normalize_response_actions()` in `rules.py` to handle legacy `response_actions` format (strings like `["create_alert"]` vs expected dict format `[{"type": "create_alert", "config": {}}]`)
- [x] Fixed `/api/v1/threat-intel/indicators` 500 error - Changed `ind.metadata` to `ind.extra_data` in `threat_intel.py` (3 occurrences) since model column is named `extra_data` but code was accessing SQLAlchemy's built-in `metadata` attribute

---

## Testing Completed

- [x] API Push ingestion end-to-end test
  - Created api_push source type via API
  - Pushed events via `/api/v1/logs/ingest` with API key header
  - Verified events stored in database
  - Verified events retrievable via `/api/v1/events`
  - Verified source metadata (event_count, last_event_at) updated

---

## Test Suite Improvements (January 2026)

### Phase 1: Test Infrastructure - COMPLETE
- [x] Expanded `backend/tests/conftest.py` with shared fixtures
  - mock_db_session, mock_redis, freeze_time
  - sample_device, sample_event, sample_alert, sample_user, sample_source, sample_rule
  - auth_headers fixtures for different user roles
  - generate_events factory fixture
- [x] Created `backend/tests/factories.py`
  - DeviceFactory, EventFactory, AlertFactory
  - UserFactory, SourceFactory, RuleFactory
  - Each with build() method and specialized builders

### Phase 2.1: Custom Parser Tests - COMPLETE
- [x] Created `backend/tests/parsers/test_custom_parser.py`
  - Pattern matching tests (single, multiple patterns)
  - Named capture groups for standard fields
  - Timestamp parsing with custom formats
  - Severity mapping tests
  - Field mapping configuration tests
  - Edge cases (empty input, unicode, IPv6)

### Phase 3.1: Error Handler Tests - COMPLETE
- [x] Created `backend/tests/collectors/test_error_handler.py`
  - categorize_error() for all httpx exception types
  - RetryConfig dataclass validation
  - CircuitBreaker state machine tests (CLOSED→OPEN→HALF_OPEN)
  - RetryHandler exponential backoff and max retries
  - ErrorTracker recording, rate calculation, summary generation

### Phase 3.2-3.5: Collector Tests - COMPLETE
- [x] Created `backend/tests/collectors/test_file_collector.py`
  - FileWatchCollector initialization
  - File opening with position tracking (read_from_end)
  - Line reading with batch limits
  - Start/stop lifecycle
  - test_connection() method tests
  - FileEventHandler tests
- [x] Created `backend/tests/collectors/test_registry.py`
  - CollectorRegistry.register() and get() methods
  - list_collectors() and is_registered() tests
  - @register_collector decorator tests
  - get_collector() convenience function tests
- [x] Created `backend/tests/collectors/test_udp_listener_collector.py`
  - UDPListenerCollector initialization with queue_size, allowed_sources
  - UDP transport creation and cleanup
  - Source IP filtering in collect()
  - UDPServerProtocol datagram handling tests
  - test_connection() port binding tests
- [x] Improved `backend/tests/collectors/test_api_pull_collector.py`
  - HTTP error handling tests (401, 429, 500)
  - Circuit breaker integration tests
  - Retry behavior tests
  - POST method tests
  - collect() async generator tests
  - Timeout configuration tests
  - Error tracking tests
  - Timestamp and offset pagination tests

### Phase 4: Service Test Improvements - COMPLETE
- [x] Expanded `backend/tests/services/test_pattern_service.py` with 8 new test classes
  - get_pattern_by_hash, get_pattern_by_id
  - get_pattern_stats, mark_pattern_ignored
  - get_patterns_for_source, get_pattern_count
  - delete_pattern, record_pattern (fixed mock)

### Phase 5: API Tests - COMPLETE
- [x] Cleaned up `backend/tests/api/test_semantic_api.py`
  - Removed 12 useless Pydantic model tests
  - Kept router setup, endpoint paths, HTTP methods tests
- [x] Created `backend/tests/api/test_auth_api.py`
  - Login tests (valid/invalid credentials, disabled user)
  - 2FA verification flow tests
  - Token refresh tests
  - Password change validation tests
  - Role requirement tests
- [x] Created `backend/tests/api/test_devices_api.py`
  - List devices with pagination/filters
  - Get device (found/not found)
  - Update device tests
  - Quarantine/release device tests
  - Tag management tests (add/remove/bulk)
  - Export CSV tests
- [x] Created `backend/tests/api/test_alerts_api.py`
  - List alerts with pagination/filters
  - Get/acknowledge/resolve alert tests
  - Mark false positive tests
  - LLM analysis trigger tests
  - Authorization tests

### Phase 2.2-2.3: Parser Improvements - COMPLETE
- [x] Added NetFlow v9 tests to `backend/tests/parsers/test_netflow_parser.py`
  - Template parsing and caching
  - Data flowset parsing with templates
  - Template update/override behavior
  - Mixed template/data packets
  - Multiple data records in one flowset
  - Options template handling (skipped)
  - Header truncation handling
- [x] Added severity detection tests
  - Port scan detection (many packets, few bytes)
  - SYN flood detection
  - Normal traffic severity (DEBUG)
- [x] Added field extraction tests
  - Alternative JSON field names (source_ip, octets)
  - Missing timestamp handling
  - Exporter IP configuration
- [x] Added sFlow binary parsing tests to `backend/tests/parsers/test_sflow_parser.py`
  - Complete flow sample parsing from binary
  - Raw packet header extraction (Ethernet/IP/TCP/UDP)
  - Multiple flow samples in one datagram
  - Counter samples with include_counters option
  - Expanded flow samples (type 3)
  - Mixed sample types
  - UDP and ICMP protocol handling
  - Agent IP extraction
- [x] Added VLAN parsing tests
  - VLAN tag extraction from 802.1Q headers
- [x] Added IPv6 tests
  - IPv6 packet parsing in flow samples
  - IPv6 agent address handling
- [x] Added edge case tests
  - Truncated samples
  - Unknown sample types
  - Empty flow samples
  - Unknown record types

### Phase 2.4: Cross-Parser Improvements - COMPLETE
- [x] Created `backend/tests/parsers/test_cross_parser.py` with 49 tests
  - Unicode handling tests (13 tests)
    - JSON, Syslog, Endpoint, Custom, NetFlow, sFlow, Loki parsers
    - Chinese, Russian, Arabic, emoji characters
  - Boundary condition tests (16 tests)
    - Very long strings (100KB messages)
    - Empty values, null fields, empty objects
    - Whitespace handling
    - Special characters (tabs, newlines, control chars)
  - Malformed input tests (12 tests)
    - Invalid data types (numbers, booleans, None)
    - Invalid timestamps, far-future timestamps
    - Invalid IP addresses
    - Deeply nested data, large arrays
  - IPv6 address tests (5 tests)
    - Full and compressed IPv6 formats
    - IPv4-mapped IPv6 addresses
  - Concurrent parsing tests (3 tests)
    - Parser state isolation

### Test Count Summary
- Total tests: 488 → 804
- New test files created: 8
- Existing files improved: 5
