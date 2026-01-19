# Backend Dockerfile for NetGuardian AI

# =============================================================================
# Base stage with Python
# =============================================================================
FROM python:3.12-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Development stage
# =============================================================================
FROM base as development

# Install dev dependencies
COPY pyproject.toml README.md ./
RUN pip install -e ".[dev]"

# Copy application code
COPY . .

# Development command with hot reload
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# =============================================================================
# Production stage
# =============================================================================
FROM base as production

# Copy only requirements first for caching
COPY pyproject.toml README.md ./

# Install production dependencies only
RUN pip install .

# Copy application code
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

# Production command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

# Default to production
FROM production
