package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	postgresadapter "github.com/paagoduura/provisioning/internal/adapters/postgres"
	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/audit"
	"github.com/paagoduura/provisioning/internal/config"
	httpapi "github.com/paagoduura/provisioning/internal/httpapi"
	"github.com/paagoduura/provisioning/internal/service"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid_config", "error", err)
		os.Exit(1)
	}
	var repo service.Repository
	var auditSink service.AuditPort
	var attestationRepo attestation.ChallengeRepository
	var attestationRecords attestation.AttestationRecordRepository
	var revocationChecker attestation.RevocationChecker
	var pool *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		pool, err = pgxpool.New(context.Background(), cfg.DatabaseURL)
		if err != nil {
			log.Error("database_config_failed", "error", err)
			os.Exit(1)
		}
		pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err != nil {
			pool.Close()
			log.Error("database_unavailable", "error", err)
			os.Exit(1)
		}
		defer pool.Close()
		repo = postgresadapter.NewSessionRepository(pool)
		auditSink = postgresadapter.NewAuditSink(pool)
		attestationRepo = postgresadapter.NewAttestationRepository(pool)
		attestationRecords = postgresadapter.NewAttestationRepository(pool)
		revocationChecker = attestationRepo.(attestation.RevocationChecker)
		log.Info("persistence_selected", "provider", "supabase_postgres")
	} else {
		repo = memory.NewSessionRepository()
		auditSink = audit.NewMemorySink()
		memoryAttestation := memory.NewAttestationRepository()
		attestationRepo = memoryAttestation
		attestationRecords = memoryAttestation
		revocationChecker = memoryAttestation
		log.Warn("persistence_selected", "provider", "memory", "warning", "development_only")
	}
	provisioning := service.New(repo, mock.CryptoService{}, mock.InterswitchAdapter{}, auditSink)
	attestationService := attestation.New(attestationRepo, attestationRecords, attestation.HSMVerifier{Client: attestation.UnavailableHSM{}}, provisioning, auditSink)
	attestationService.SetRevocationChecker(revocationChecker)
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: httpapi.New(log, provisioning, attestationService, cfg.MaxRequestBodyBytes).Routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Info("api_started", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("api_failed", "error", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown_failed", "error", err)
		os.Exit(1)
	}
	log.Info("api_stopped")
}
