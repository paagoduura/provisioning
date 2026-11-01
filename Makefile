.PHONY: run test fmt vet e2e-staging

run:
	go run ./cmd/api

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

vet:
	go vet ./...

e2e-staging:
	pwsh -NoProfile -File ./scripts/staging-kms-e2e.ps1
