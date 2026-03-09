.DEFAULT_GOAL := help

DB_URL ?= postgresql://unibo_user:unibo_pass@localhost:5432/unibo_toolkit?sslmode=disable
MIGRATIONS_DIR ?= ../databases/migrations

.PHONY: setup
setup:
	@echo "==> Installing dependencies..."
	go mod download
	@echo "\n==> Setting up .env..."
	@test -f .env || cp .env.example .env
	@echo "\n==> Generating RSA keys..."
	@mkdir -p keys
	@if [ ! -f keys/private.pem ]; then \
		openssl genrsa -out keys/private.pem 2048; \
		openssl rsa -in keys/private.pem -pubout -out keys/public.pem; \
		echo "RSA keys generated"; \
	else \
		echo "RSA keys already exist"; \
	fi
	@echo "\n==> Checking databases repo..."
	@if [ ! -d "../databases" ]; then \
		cd .. && git clone https://github.com/unibo-toolkit/databases.git; \
	else \
		echo "databases repo already exists"; \
	fi
	@echo "\n[OK] Setup complete! Next steps:"
	@echo "  1. Edit .env with your OAuth credentials"
	@echo "  2. Run: make dev-up"
	@echo "  3. Run: make migrate-up"
	@echo "  4. Run: make run"

.PHONY: dev-up
dev-up:
	docker compose -f docker-compose.dev.yaml up -d postgres redis
	@echo "Waiting for PostgreSQL to be ready..."
	@until docker compose -f docker-compose.dev.yaml exec postgres pg_isready -U unibo_user > /dev/null 2>&1; do sleep 1; done
	@echo "[OK] PostgreSQL is ready!"
	@echo "[OK] Redis is ready!"
	@echo "\nNext: run 'make migrate-up' to apply migrations"

.PHONY: dev-down
dev-down:
	docker compose -f docker-compose.dev.yaml down

.PHONY: dev-clean
dev-clean:
	docker compose -f docker-compose.dev.yaml down -v
	@echo "[WARNING] All data removed!"

.PHONY: migrate-up
migrate-up:
	@if [ ! -d "$(MIGRATIONS_DIR)" ]; then \
		echo "[ERROR] $(MIGRATIONS_DIR) not found!"; \
		echo "Run 'make setup' first to clone databases repo"; \
		exit 1; \
	fi
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" up
	@echo "[OK] Migrations applied!"

.PHONY: migrate-down
migrate-down:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" down 1

.PHONY: migrate-version
migrate-version:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" version

.PHONY: sqlc
sqlc:
	@echo "==> Generating models with sqlc..."
	cd internal/storage && sqlc generate
	@echo "[OK] Models generated in internal/repository/db/"

.PHONY: build
build:
	CGO_ENABLED=0 go build -o bin/auth-service ./cmd/server/main.go

.PHONY: clean
clean:
	rm -rf bin/ coverage.out keys/*.pem
	@echo "[OK] Cleaned up"

.PHONY: help
help:
	@echo "Auth Service - Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make setup          # First time setup"
	@echo "  2. make dev-up         # Start postgres + redis"
	@echo "  3. make migrate-up     # Apply migrations"
	@echo "  4. make sqlc           # Generate models"
	@echo "  5. make run            # Run service"
