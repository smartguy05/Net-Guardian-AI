#!/bin/bash
set -e

# NetGuardian AI Docker Entrypoint
# Supports running different modes via environment variable or command argument

MODE="${NETGUARDIAN_MODE:-api}"

# If arguments are passed, use them directly
if [ $# -gt 0 ]; then
    exec "$@"
fi

# Otherwise, run based on MODE
case "$MODE" in
    api)
        echo "Starting NetGuardian API server..."
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
        ;;
    worker|collector)
        echo "Starting NetGuardian Collector Worker..."
        exec python -m app.worker
        ;;
    migrations)
        echo "Running database migrations..."
        exec alembic upgrade head
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Valid modes: api, worker, collector, migrations"
        exit 1
        ;;
esac
