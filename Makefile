.PHONY: all lint fmt test run

# Commands
GO       := go
GOLINT   := golangci-lint
GOMOD    := $(GO) mod
GOINSTALL:= $(GO) install

# Directories
CMD_DIR  := ./cmd/merkle-tree
TESTS    := ./tests

all: lint fmt test run

lint:
	@echo "Running linter..."
	@$(GOLINT) run ./...

fmt:
	@echo "Formatting code..."
	@$(GO) fmt ./...

test:
	@echo "Running tests..."
	@$(GO) test $(TESTS)

run:
	@echo "Running main program..."
	@$(GO) run $(CMD_DIR)/main.go

install-lint:
	@echo "Installing linter..."
	@$(GOINSTALL) github.com/golangci/golangci-lint/cmd/golangci-lint@latest

tidy:
	@echo "Tidying up module..."
	@$(GOMOD) tidy

clean:
	@echo "Cleaning up..."
	@rm -rf ./bin ./build

help:
	@echo "Available targets:"
	@echo "  all          Run lint, fmt, test, and run"
	@echo "  lint         Run linter"
	@echo "  fmt          Format the code"
	@echo "  test         Run tests"
	@echo "  run          Run the main program"
	@echo "  install-lint Install golangci-lint"
	@echo "  tidy         Tidy up the module"
	@echo "  clean        Clean up build artifacts"
	@echo "  help         Show this help message"
