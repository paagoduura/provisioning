.PHONY: run test test-integration retention-purge backup-rehearsal local-deps local-app local-down fmt vet

export PGSERVICE SOURCE_DB OUTPUT_DIR

run:
	go run ./cmd/api

test:
	go test ./...

test-integration:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL must point to a disposable PostgreSQL database" >&2; exit 2)
	go test -tags=integration -race -count=1 ./internal/integration/...

# One bounded purge invocation. All approved retention windows and a batch size
# must be supplied explicitly by the operator; this target is never scheduled.
retention-purge:
	go run ./cmd/retention-purge

# Local-only, disposable logical-backup/restore rehearsal. PGSERVICE and
# SOURCE_DB identify the local source; output artifacts are private by default.
backup-rehearsal:
	./scripts/postgres-backup-rehearsal.sh

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
