# Foundation slice acceptance checklist

| Criterion | Status | Evidence |
|---|---|---|
| Deployable Go service | Complete | `cmd/api/main.go`, `Dockerfile` |
| Health and readiness endpoints | Complete | `/healthz`, `/readyz`; readiness checks configured runtime dependencies |
| Typed environment configuration | Complete | `internal/config/config.go` |
| Security baseline middleware | Complete | request limits, secure headers, correlation IDs |
| Observability | Complete | structured JSON logs with status and duration |
| Audit event emission | Complete | `internal/audit`, session creation event |
| Threat model/security scope | Complete for foundation | `SECURITY.md`; production certification remains later work |
| API versioning | Complete | `/v1/...` routes |
| Tests and static checks | Complete | `go test ./...`, `go vet ./...` |
| Real HSM, Interswitch, hardware | Intentionally deferred | Requires approved contracts, credentials, and test hardware |
