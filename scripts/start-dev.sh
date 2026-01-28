#!/bin/bash
# NetGuardian AI - Development Environment Startup Script (Linux)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Options
SEED_DATA=false
SKIP_CONTAINERS=false
USE_DOCKER=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --seed-data)
            SEED_DATA=true
            shift
            ;;
        --skip-containers)
            SKIP_CONTAINERS=true
            shift
            ;;
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --help|-h)
            echo "NetGuardian AI Development Startup Script (Linux)"
            echo ""
            echo "Usage: ./scripts/start-dev.sh [options]"
            echo ""
            echo "Options:"
            echo "    --seed-data       Load demo data into the database"
            echo "    --skip-containers Skip starting containers (if already running)"
            echo "    --docker          Use Docker instead of Podman"
            echo "    --help, -h        Show this help message"
            echo ""
            echo "Examples:"
            echo "    ./scripts/start-dev.sh                    # Start everything"
            echo "    ./scripts/start-dev.sh --seed-data        # Start and load demo data"
            echo "    ./scripts/start-dev.sh --docker           # Use Docker instead of Podman"
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
    COMPOSE_CMD="docker-compose"
else
    if command -v podman &> /dev/null; then
        CONTAINER_CMD="podman"
        COMPOSE_CMD="podman-compose"
    elif command -v docker &> /dev/null; then
        CONTAINER_CMD="docker"
        COMPOSE_CMD="docker-compose"
    else
        echo -e "${RED}Error: Neither Podman nor Docker found. Please install one.${NC}"
        exit 1
    fi
fi

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  NetGuardian AI - Development Startup${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  Using: $CONTAINER_CMD"
echo ""

# Step 1: Start containers
if ! $SKIP_CONTAINERS; then
    echo -e "${YELLOW}[1/5] Starting database and Redis containers...${NC}"

    # Check if containers exist
    if $CONTAINER_CMD ps -a --format "{{.Names}}" 2>/dev/null | grep -q "netguardian-db"; then
        echo "  Starting existing containers..."
        $CONTAINER_CMD start netguardian-db netguardian-redis 2>/dev/null || true
    else
        echo "  Creating containers..."
        $CONTAINER_CMD run -d --name netguardian-db \
            -e POSTGRES_USER=netguardian \
            -e POSTGRES_PASSWORD=netguardian-dev-password \
            -e POSTGRES_DB=netguardian \
            -p 5432:5432 \
            timescale/timescaledb:latest-pg16

        $CONTAINER_CMD run -d --name netguardian-redis \
            -p 6379:6379 \
            redis:7-alpine
    fi

    # Wait for database to be ready
    echo "  Waiting for database to be ready..."
    sleep 5
    for i in {1..30}; do
        if $CONTAINER_CMD exec netguardian-db pg_isready -U netguardian &>/dev/null; then
            echo -e "  ${GREEN}Database ready${NC}"
            break
        fi
        sleep 1
    done
fi

# Step 2: Ensure backend .env exists
echo -e "${YELLOW}[2/5] Checking backend configuration...${NC}"
ENV_FILE="$PROJECT_ROOT/backend/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "  Creating backend/.env..."
    cat > "$ENV_FILE" << 'EOF'
DATABASE_URL=postgresql+asyncpg://netguardian:netguardian-dev-password@localhost:5432/netguardian
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key-change-in-production-must-be-64-chars-hex
DEBUG=true
LOG_LEVEL=DEBUG
EOF
fi
echo -e "  ${GREEN}Backend configuration ready${NC}"

# Step 3: Install dependencies if needed
echo -e "${YELLOW}[3/5] Checking dependencies...${NC}"
cd "$PROJECT_ROOT/backend"

# Create virtual environment if it doesn't exist
if [[ ! -d ".venv" ]]; then
    echo "  Creating Python virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate
echo "  Using virtual environment: $VIRTUAL_ENV"

# Install backend dependencies
echo "  Installing backend dependencies..."
pip install -q -e . 2>/dev/null || pip install -e .

cd "$PROJECT_ROOT/frontend"
if [[ ! -d "node_modules" ]]; then
    echo "  Installing frontend dependencies..."
    npm install
fi
echo -e "  ${GREEN}Dependencies ready${NC}"

# Step 4: Run migrations
echo -e "${YELLOW}[4/5] Running database migrations...${NC}"
cd "$PROJECT_ROOT/backend"
.venv/bin/alembic upgrade head
echo -e "  ${GREEN}Migrations complete${NC}"

# Seed data if requested
if $SEED_DATA; then
    echo "  Loading demo data..."
    .venv/bin/python scripts/seed_demo_data.py
    echo -e "  ${GREEN}Demo data loaded${NC}"
fi

# Step 5: Start servers
echo -e "${YELLOW}[5/5] Starting servers...${NC}"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo -e "${GREEN}Done.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# Start backend
echo "  Starting backend on port 8000..."
cd "$PROJECT_ROOT/backend"
.venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Start frontend
echo "  Starting frontend on port 5173..."
cd "$PROJECT_ROOT/frontend"
npm run dev &
FRONTEND_PID=$!

sleep 3

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  NetGuardian AI is running!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  ${CYAN}Frontend:  http://localhost:5173${NC}"
echo -e "  ${CYAN}Backend:   http://localhost:8000${NC}"
echo -e "  ${CYAN}API Docs:  http://localhost:8000/docs${NC}"
echo ""
if $SEED_DATA; then
    echo -e "  ${YELLOW}Demo Credentials:${NC}"
    echo "    Admin:    demo_admin / DemoAdmin123!"
    echo "    Operator: demo_operator / DemoOp123!"
    echo "    Viewer:   demo_viewer / DemoView123!"
    echo ""
fi
echo "  Press Ctrl+C to stop all servers"
echo ""

# Wait for processes
wait
