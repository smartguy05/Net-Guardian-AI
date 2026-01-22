#!/bin/bash
# NetGuardian AI - Stop Development Environment (Linux)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

STOP_CONTAINERS=false
USE_DOCKER=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --stop-containers)
            STOP_CONTAINERS=true
            shift
            ;;
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --help|-h)
            echo "Usage: ./scripts/stop-dev.sh [options]"
            echo ""
            echo "Options:"
            echo "    --stop-containers  Also stop database and Redis containers"
            echo "    --docker           Use Docker instead of Podman"
            echo "    --help, -h         Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Detect container runtime
if $USE_DOCKER; then
    CONTAINER_CMD="docker"
elif command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
else
    CONTAINER_CMD="docker"
fi

echo -e "${YELLOW}Stopping NetGuardian AI...${NC}"

# Kill backend (uvicorn)
pkill -f "uvicorn app.main:app" 2>/dev/null && echo -e "  ${GREEN}Backend stopped${NC}" || echo "  Backend not running"

# Kill frontend (vite)
pkill -f "vite" 2>/dev/null && echo -e "  ${GREEN}Frontend stopped${NC}" || echo "  Frontend not running"

# Kill anything on ports 5173 and 8000
for port in 5173 8000; do
    pid=$(lsof -t -i:$port 2>/dev/null)
    if [[ -n "$pid" ]]; then
        kill $pid 2>/dev/null
    fi
done

# Stop containers if requested
if $STOP_CONTAINERS; then
    echo "  Stopping containers..."
    $CONTAINER_CMD stop netguardian-db netguardian-redis 2>/dev/null
    echo -e "  ${GREEN}Containers stopped${NC}"
fi

echo -e "${GREEN}Done.${NC}"
