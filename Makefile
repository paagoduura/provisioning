.PHONY: run test fmt vet

run:
	go run ./cmd/api

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

vet:
	go vet ./...
