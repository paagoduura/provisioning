.PHONY: run test fmt vet e2e-staging e2e-staging-gate

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

e2e-staging-gate:
	pwsh -NoProfile -File ./scripts/run-staging-kms-gate.ps1
