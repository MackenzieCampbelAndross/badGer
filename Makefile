.PHONY: all build build-agent build-control-plane build-frontend test test-linux adversarial bench clean

all: build test

build: build-agent build-control-plane build-frontend

build-agent:
	cargo build --release -p badger-agent

build-control-plane:
	cd control-plane && go build -v ./cmd/badger-server

build-frontend:
	cd frontend && npm install && npm run build

test:
	cargo test
	cd control-plane && go test -v ./...

test-linux:
	wsl -d Ubuntu-22.04 -u root -- bash -c "cd /mnt/d/Mac/project/badger && source /root/.cargo/env && cargo test && cd control-plane && go test -v ./..."

adversarial:
	wsl -d Ubuntu-22.04 -u root -- bash -c "cd /mnt/d/Mac/project/badger && source /root/.cargo/env && cargo run -p badger-agent -- adversarial"

bench:
	wsl -d Ubuntu-22.04 -u root -- bash -c "cd /mnt/d/Mac/project/badger && source /root/.cargo/env && cargo run -p badger-agent --release -- benchmark"

clean:
	cargo clean
	rm -rf control-plane/badger-server frontend/dist
