# BADGER Deployment & Operations Guide

---

## 1. Local Development & Testing

### Using WSL2 (Ubuntu 22.04) or Native Linux
```bash
# 1. Run all unit tests
make test-linux

# 2. Run adversarial verification scenarios (A through H)
make adversarial

# 3. Run performance benchmarks
make bench
```

---

## 2. Running Standalone Components

### Control Plane
```bash
cd control-plane
go run ./cmd/badger-server
```
Starts REST server on `http://localhost:8080`.

### Operator Dashboard
```bash
cd frontend
npm install
npm run dev
```
Starts development server on `http://localhost:3000` with proxy to `:8080`.

### Sandboxed Workload Execution
```bash
# Execute bash command inside full Linux containment
cargo run -p badger-agent -- run --workload test-agent -- /bin/echo "Hello from BADGER sandbox"
```

---

## 3. Docker Compose Deployment

```bash
docker compose -f deployment/compose/docker-compose.yml up --build
```
Services started:
- `control-plane`: Go API server on port 8080.
- `frontend`: React web console on port 3000.
- `agent-sandbox`: Linux container with `SYS_ADMIN` capability for testing host sandbox operations.
