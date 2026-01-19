# NetGuardian AI - Todo List

Remaining tasks organized by phase and priority.

**Completed:** Phase 1, Phase 2, Phase 3, Phase 4
**Current:** Phase 5 (Polish & Extensions)

---

## Phase 5: Polish & Extensions (Current)

- [x] Add Ollama API monitoring (LLM-malware detection)
- [ ] Create optional endpoint agent
- [ ] Add NetFlow/sFlow support
- [ ] Performance optimization
- [ ] Security hardening review
- [ ] Write deployment documentation
- [ ] Write user guide

---

## Technical Debt

- [ ] Add comprehensive error handling in collectors
- [ ] Add retry logic for API collectors
- [ ] Add connection pooling configuration
- [ ] Add request/response logging middleware
- [ ] Add API rate limiting
- [ ] Add input validation for all endpoints
- [ ] Set up CI/CD pipeline

---

## Documentation

- [x] README.md - Project overview
- [x] docs/implementation-status.md - Status tracking
- [x] docs/prd.md - Product requirements
- [x] .memories/completed.md - Completed tasks
- [x] .memories/todos.md - Todo list
- [x] .memories/notes.md - Development notes
- [x] API documentation (auto-generated at /docs)
- [ ] Deployment guide for different platforms
- [ ] Configuration reference
- [ ] Troubleshooting guide
- [ ] Contributing guidelines

---

## Completed Phases

### Phase 4: Active Response - COMPLETE
- [x] Implement AdGuard Home blocking integration
- [x] Implement router integration (UniFi, pfSense/OPNsense)
- [x] Create response playbook engine with triggers and actions
- [x] Implement audit logging system
- [x] Add quarantine management UI
- [x] Create quarantine service with integration orchestration
- [x] Write tests for Phase 4 (45 tests)

### Phase 3: LLM Integration - COMPLETE
- [x] Create Claude API integration service with prompt caching
- [x] Implement alert triage with LLM analysis
- [x] Add natural language query endpoint
- [x] Create chat UI component
- [x] Add incident summarization
- [x] Write tests for LLM integration (22 tests)

### Phase 2: Anomaly Detection - COMPLETE
- [x] Design baseline engine architecture
- [x] Implement per-device behavioral profiling
- [x] Implement DNS query pattern tracking
- [x] Implement z-score anomaly detection
- [x] Create anomaly detection service
- [x] Implement alert generation from anomalies
- [x] Create anomalies UI page
- [x] Write tests (30 tests)

### Phase 1: Foundation - COMPLETE
- [x] Project scaffolding
- [x] Database layer with TimescaleDB
- [x] Authentication system with JWT
- [x] Device inventory management
- [x] Log source configuration
- [x] Event ingestion (API pull, file watch, API push)
- [x] Basic dashboard UI
- [x] User management UI
