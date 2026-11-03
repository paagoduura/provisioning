package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jackc/pgx/v5"
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
		poolConfig, parseErr := pgxpool.ParseConfig(cfg.DatabaseURL)
		if parseErr != nil {
			log.Error("database_config_failed", "error", parseErr)
			os.Exit(1)
		}
		// Supabase transaction pooling (port 6543) does not preserve named
		// prepared statements across connections. Simple protocol works for
		// both pooled and direct PostgreSQL connections.
		poolConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		pool, err = pgxpool.NewWithConfig(context.Background(), poolConfig)
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
	var verifier attestation.Verifier = attestation.UnavailableVerifier{}
	if cfg.AWSKMSKeyID != "" {
		algorithm, algorithmErr := attestation.ParseKMSAlgorithm(cfg.AWSKMSSigningAlgorithm)
		if algorithmErr != nil {
			log.Error("kms_config_failed", "error", algorithmErr)
			os.Exit(1)
		}
		awsOptions := []func(*awscfg.LoadOptions) error{awscfg.WithRegion(cfg.AWSRegion)}
		if awsProfile := os.Getenv("AWS_PROFILE"); awsProfile != "" {
			awsOptions = append(awsOptions, awscfg.WithSharedConfigProfile(awsProfile))
		}
		awsConfig, awsErr := awscfg.LoadDefaultConfig(context.Background(), awsOptions...)
		if awsErr != nil {
			log.Error("aws_config_failed", "error", awsErr)
			os.Exit(1)
		}
		verifier = attestation.KMSVerifier{Client: kms.NewFromConfig(awsConfig), KeyID: cfg.AWSKMSKeyID, Algorithm: algorithm}
		log.Info("attestation_verifier_selected", "provider", attestation.KMSProvider, "region", cfg.AWSRegion)
	} else {
		log.Warn("attestation_verifier_selected", "provider", "unavailable", "warning", "set AWS_KMS_KEY_ID or configure the HSM adapter before production use")
	}
	attestationService := attestation.New(attestationRepo, attestationRecords, verifier, provisioning, auditSink)
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
