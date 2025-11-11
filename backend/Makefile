.PHONY: help build run dev clean test deps setup

# Default target
help:
	@echo "Compliance Monitoring Backend - Make targets"
	@echo "============================================"
	@echo ""
	@echo "  make setup      - Initial setup (install deps, create binary)"
	@echo "  make deps       - Download Go dependencies"
	@echo "  make build      - Build the binary"
	@echo "  make run        - Run the server (loads .env)"
	@echo "  make dev        - Run with go run (for development)"
	@echo "  make test       - Run API tests"
	@echo "  make clean      - Remove built binaries"
	@echo ""

# Setup everything
setup:
	@./setup.sh

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	@go mod download
	@go mod tidy
	@echo "✓ Dependencies installed"

# Build binary
build:
	@echo "🔨 Building binary..."
	@go build -o compliance-monitor main.go
	@echo "✓ Binary built: ./compliance-monitor"

# Run the server (production mode)
run: build
	@echo "🚀 Starting server..."
	@if [ ! -f .env ]; then \
		echo "❌ .env file not found. Please create it first."; \
		exit 1; \
	fi
	@export $$(cat .env | xargs) && ./compliance-monitor

# Run in development mode
dev:
	@echo "🔧 Running in development mode..."
	@if [ ! -f .env ]; then \
		echo "❌ .env file not found. Please create it first."; \
		exit 1; \
	fi
	@export $$(cat .env | xargs) && go run main.go

# Run API tests
test:
	@./test-api.sh

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -f compliance-monitor
	@echo "✓ Cleaned"

# Quick restart (for development)
restart: clean build run
