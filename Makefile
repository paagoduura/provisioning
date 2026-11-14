.PHONY: run test test-integration local-deps local-app local-down fmt vet

run:
	go run ./cmd/api

test:
	go test ./...

test-integration:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL must point to a disposable PostgreSQL database" >&2; exit 2)
	go test -tags=integration -race -count=1 ./internal/integration/...

local-deps:
	docker compose up -d postgres redis

local-app:
	docker compose --profile application up --build

local-down:
	docker compose --profile application down

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

vet:
	go vet ./...
