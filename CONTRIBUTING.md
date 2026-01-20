# Contributing to NetGuardian AI

Thank you for your interest in contributing to NetGuardian AI! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Issue Guidelines](#issue-guidelines)

---

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels and backgrounds.

---

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Net-Guardian-AI.git
   cd Net-Guardian-AI
   ```
3. **Set up the development environment** (see below)
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker and Docker Compose (or Podman)
- PostgreSQL 16+ with TimescaleDB extension
- Redis 7+

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies with dev extras
pip install -e ".[dev]"

# Run linting
ruff check app/ tests/

# Run type checking
mypy app/

# Run tests
pytest tests/ -v
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Run linting
npm run lint

# Build for production
npm run build
```

### Running with Docker

```bash
cd deploy

# Copy environment template
cp .env.example .env
# Edit .env with your settings

# Start services
docker-compose up -d

# View logs
docker-compose logs -f backend
```

---

## Project Structure

```
Net-Guardian-AI/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── api/v1/         # API endpoints
│   │   ├── collectors/     # Data collectors
│   │   ├── core/           # Core utilities (auth, cache, etc.)
│   │   ├── events/         # Event bus
│   │   ├── models/         # SQLAlchemy models
│   │   ├── parsers/        # Log parsers
│   │   └── services/       # Business logic
│   ├── tests/              # Backend tests
│   └── alembic/            # Database migrations
├── frontend/               # React frontend
│   ├── src/
│   │   ├── api/           # API hooks and client
│   │   ├── components/    # React components
│   │   ├── pages/         # Page components
│   │   └── stores/        # Zustand stores
│   └── public/
├── deploy/                 # Deployment configs
│   ├── docker-compose.yml
│   └── Dockerfile.*
└── docs/                   # Documentation
```

---

## Coding Standards

### Backend (Python)

- **Style**: Follow PEP 8 with Ruff formatter
- **Type hints**: Use type hints for all functions
- **Docstrings**: Google-style docstrings for public functions
- **Line length**: 88 characters (Ruff default)

```python
async def process_event(
    event: RawEvent,
    session: AsyncSession,
) -> ProcessResult:
    """Process a raw event and store it.

    Args:
        event: The raw event to process.
        session: Database session.

    Returns:
        Processing result with status and metadata.

    Raises:
        ProcessingError: If event processing fails.
    """
    ...
```

### Frontend (TypeScript/React)

- **Style**: ESLint with TypeScript rules
- **Components**: Functional components with hooks
- **State**: Zustand for global state, React Query for server state
- **Styling**: Tailwind CSS with dark mode support

```typescript
interface Props {
  device: Device;
  onSelect: (id: string) => void;
}

export function DeviceCard({ device, onSelect }: Props) {
  return (
    <div
      className="p-4 bg-white dark:bg-slate-800 rounded-lg"
      onClick={() => onSelect(device.id)}
    >
      {/* ... */}
    </div>
  );
}
```

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Tests
- `chore`: Maintenance tasks

Examples:
```
feat(collectors): add retry logic for API collectors
fix(auth): handle expired refresh tokens correctly
docs(readme): update installation instructions
```

---

## Testing

### Backend Tests

```bash
cd backend

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/parsers/test_adguard_parser.py -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html

# Run tests matching pattern
pytest -k "test_anomaly" -v
```

### Test Structure

```python
import pytest
from app.services.anomaly_service import AnomalyService

@pytest.fixture
def anomaly_service():
    return AnomalyService()

async def test_detect_volume_spike(anomaly_service):
    """Test that volume spikes are detected correctly."""
    result = await anomaly_service.detect(device_id="test", events=events)
    assert result.anomaly_type == "volume_spike"
```

### Frontend Tests

```bash
cd frontend

# Run tests (if configured)
npm run test
```

---

## Submitting Changes

### Pull Request Process

1. **Ensure all checks pass**:
   - Backend: `ruff check`, `mypy`, `pytest`
   - Frontend: `npm run lint`, `npm run build`

2. **Update documentation** if needed

3. **Create a pull request**:
   - Use a descriptive title
   - Reference related issues
   - Describe your changes

4. **Wait for review**:
   - Address feedback
   - Keep PR focused (one feature/fix per PR)

### PR Title Format

```
type(scope): description (#issue)
```

Examples:
```
feat(topology): add network topology visualization (#123)
fix(alerts): correct severity filtering (#456)
```

### PR Description Template

```markdown
## Summary
Brief description of changes.

## Changes
- Added X
- Fixed Y
- Updated Z

## Testing
- [ ] Added/updated tests
- [ ] All tests pass
- [ ] Manual testing completed

## Related Issues
Closes #123
```

---

## Issue Guidelines

### Bug Reports

Include:
1. **Description**: What happened?
2. **Expected behavior**: What should happen?
3. **Steps to reproduce**: How to trigger the bug?
4. **Environment**: OS, browser, versions
5. **Logs/screenshots**: If applicable

### Feature Requests

Include:
1. **Description**: What feature do you want?
2. **Use case**: Why is it needed?
3. **Proposed solution**: How should it work?
4. **Alternatives**: Other approaches considered

### Labels

- `bug`: Something isn't working
- `enhancement`: New feature request
- `documentation`: Documentation improvements
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed

---

## Development Tips

### Database Migrations

```bash
cd backend

# Create new migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

### Adding a New Parser

1. Create `backend/app/parsers/your_parser.py`
2. Implement `BaseParser` interface
3. Register with `@register_parser("your_parser")`
4. Add tests in `backend/tests/parsers/`

### Adding a New API Endpoint

1. Create route in `backend/app/api/v1/your_route.py`
2. Add Pydantic schemas for request/response
3. Include router in `backend/app/api/v1/router.py`
4. Add TypeScript types in `frontend/src/types/index.ts`
5. Add hooks in `frontend/src/api/hooks.ts`

### Debugging

```python
# Backend logging
import structlog
logger = structlog.get_logger()
logger.debug("debug_message", key="value")
```

```typescript
// Frontend debugging
console.log('Debug:', data);
```

---

## Questions?

- Open a GitHub issue
- Check existing issues and documentation

Thank you for contributing!
