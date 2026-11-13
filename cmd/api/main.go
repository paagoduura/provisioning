package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	"github.com/paagoduura/provisioning/internal/observability"
	"github.com/paagoduura/provisioning/internal/ratelimit"
	"github.com/paagoduura/provisioning/internal/readiness"
	"github.com/paagoduura/provisioning/internal/registry"
	"github.com/paagoduura/provisioning/internal/service"
	"github.com/paagoduura/provisioning/internal/supabaseauth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid_config", "error", err)
		os.Exit(1)
	}
	metrics := observability.NewMetrics(prometheus.NewRegistry())
	tracerProvider, shutdownTracing, traceErr := observability.SetupTracing(context.Background(), cfg.OTELServiceName, cfg.OTELEnvironment, cfg.OTELTracesEndpoint)
	if traceErr != nil {
		if cfg.Environment == "staging" || cfg.Environment == "production" {
			log.Error("tracing_initialization_failed", "error", traceErr)
			os.Exit(1)
		}
		log.Warn("tracing_initialization_failed", "error", traceErr)
	} else {
		defer func() { _ = shutdownTracing(context.Background()) }()
	}
	authCtx, authCancel := context.WithTimeout(context.Background(), 10*time.Second)
	authVerifier, err := supabaseauth.NewVerifier(authCtx, cfg.SupabaseAuthIssuer, cfg.SupabaseAuthAudience, nil)
	authCancel()
	if err != nil {
		log.Error("supabase_auth_initialization_failed", "error", err)
		os.Exit(1)
	}
	log.Info("authentication_selected", "provider", "supabase_auth", "issuer", cfg.SupabaseAuthIssuer, "audience", cfg.SupabaseAuthAudience)
	var repo service.Repository
	var auditSink service.AuditPort
	var attestationRepo attestation.ChallengeRepository
	var attestationRecords attestation.AttestationRecordRepository
	var revocationChecker attestation.RevocationChecker
	var deviceRegistry registry.Repository
	var pool *pgxpool.Pool
	var redisClient redis.UniversalClient
	var abuseLimiter ratelimit.Limiter
	if cfg.RedisURL != "" {
		redisOptions, parseErr := redis.ParseURL(cfg.RedisURL)
		if parseErr != nil {
			log.Error("redis_config_failed", "error", parseErr)
			os.Exit(1)
		}
		redisClient = redis.NewClient(redisOptions)
		redisCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = redisClient.Ping(redisCtx).Err()
		cancel()
		if err != nil {
			_ = redisClient.Close()
			if cfg.Environment == "staging" || cfg.Environment == "production" {
				log.Error("redis_unavailable", "error", err)
				os.Exit(1)
			}
			log.Warn("redis_unavailable", "error", err, "warning", "using development-only in-memory rate limiter")
			redisClient = nil
		} else {
			abuseLimiter = ratelimit.NewRedis(redisClient)
			defer abuseLimiter.Close()
			log.Info("rate_limiting_selected", "provider", "redis")
		}
	}
	if abuseLimiter == nil {
		if cfg.Environment == "staging" || cfg.Environment == "production" {
			log.Error("redis_required", "error", "REDIS_URL is required for distributed rate limiting")
			os.Exit(1)
		}
		abuseLimiter = ratelimit.NewMemory()
		log.Warn("rate_limiting_selected", "provider", "memory", "warning", "development_only")
	}
	if cfg.DatabaseURL != "" {
		poolConfig, parseErr := pgxpool.ParseConfig(cfg.DatabaseURL)
		if parseErr != nil {
			log.Error("database_config_failed", "error", parseErr)
			os.Exit(1)
		}
		// Supabase transaction poolers do not guarantee that a connection
		// returns to the same backend. Disable pgx prepared statements so
		// statement names cannot collide across pooled backend connections.
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
		deviceRegistry = postgresadapter.NewDeviceRegistry(pool)
		log.Info("persistence_selected", "provider", "supabase_postgres")
	} else {
		repo = memory.NewSessionRepository()
		auditSink = audit.NewMemorySink()
		memoryAttestation := memory.NewAttestationRepository()
		attestationRepo = memoryAttestation
		attestationRecords = memoryAttestation
		revocationChecker = memoryAttestation
		deviceRegistry = memory.NewDeviceRegistry()
		log.Warn("persistence_selected", "provider", "memory", "warning", "development_only")
	}
	auditSinks := []audit.Sink{auditSink, observability.NewJSONSink(log)}
	if cfg.SecurityAlertWebhookURL != "" {
		auditSinks = append(auditSinks, observability.NewWebhookAlertSink(&http.Client{Timeout: 5 * time.Second}, cfg.SecurityAlertWebhookURL, cfg.SecurityAlertWebhookSecret, log))
	}
	auditSink = &observability.AuditMetricsSink{Next: observability.NewMultiSink(auditSinks...), Metrics: metrics}
	provisioning := service.New(repo, mock.CryptoService{}, mock.InterswitchAdapter{}, auditSink)
	provisioning.SetDeviceRegistry(deviceRegistry)
	var verifier attestation.Verifier = attestation.UnavailableVerifier{}
	switch cfg.AttestationProvider {
	case "aws-kms":
		algorithm, algorithmErr := attestation.ParseKMSAlgorithm(cfg.AWSKMSSigningAlgorithm)
		if algorithmErr != nil {
			log.Error("kms_config_failed", "error", algorithmErr)
			os.Exit(1)
		}
		awsConfig, awsErr := awscfg.LoadDefaultConfig(context.Background(), awscfg.WithRegion(cfg.AWSRegion))
		if awsErr != nil {
			log.Error("aws_config_failed", "error", awsErr)
			os.Exit(1)
		}
		verifier = attestation.KMSVerifier{Client: kms.NewFromConfig(awsConfig), KeyID: cfg.AWSKMSKeyID, Algorithm: algorithm}
		log.Info("attestation_verifier_selected", "provider", attestation.KMSProvider, "region", cfg.AWSRegion, "algorithm", cfg.AWSKMSSigningAlgorithm)
	case "google-play-integrity":
		credentials := []byte(cfg.GooglePlayCredentials)
		if cfg.GooglePlayCredentialsFile != "" {
			credentials, err = os.ReadFile(cfg.GooglePlayCredentialsFile)
			if err != nil {
				log.Error("google_play_credentials_failed", "error", err)
				os.Exit(1)
			}
		}
		verifier = attestation.GooglePlayIntegrityVerifier{Client: http.DefaultClient, CredentialsJSON: credentials, PackageName: cfg.GooglePlayPackageName, RequireLicensed: cfg.GooglePlayRequireLicensed, MaxTokenAge: 5 * time.Minute, MaxClockSkew: 30 * time.Second}
		log.Info("attestation_verifier_selected", "provider", attestation.GooglePlayIntegrityProvider, "package_name", cfg.GooglePlayPackageName)
	case "apple-app-attest":
		lookup, ok := attestationRepo.(attestation.AppleAppAttestKeyLookup)
		if !ok {
			log.Error("apple_app_attest_key_store_unavailable")
			os.Exit(1)
		}
		rootPEM, readErr := os.ReadFile(cfg.AppleRootCertificateFile)
		if readErr != nil {
			log.Error("apple_app_attest_root_certificate_failed", "error", readErr)
			os.Exit(1)
		}
		rootBlock, _ := pem.Decode(rootPEM)
		if rootBlock == nil {
			log.Error("apple_app_attest_root_certificate_failed", "error", "PEM certificate not found")
			os.Exit(1)
		}
		rootCertificate, parseErr := x509.ParseCertificate(rootBlock.Bytes)
		if parseErr != nil {
			log.Error("apple_app_attest_root_certificate_failed", "error", parseErr)
			os.Exit(1)
		}
		roots := x509.NewCertPool()
		roots.AddCert(rootCertificate)
		verifier = attestation.AppleAppAttestVerifier{Root: roots, TeamID: cfg.AppleTeamID, BundleID: cfg.AppleBundleID, Environment: cfg.AppleEnvironment, Keys: lookup}
		log.Info("attestation_verifier_selected", "provider", attestation.AppleAppAttestProvider, "environment", cfg.AppleEnvironment, "bundle_id", cfg.AppleBundleID)
	case "cloudhsm-pkcs11":
		log.Error("attestation_verifier_unavailable", "provider", cfg.AttestationProvider, "error", "provider adapter and external trust configuration are not installed")
	default:
		log.Warn("attestation_verifier_selected", "provider", "unavailable", "warning", "set ATTESTATION_PROVIDER and configure its approved verifier before production use")
	}
	attestationService := attestation.New(attestationRepo, attestationRecords, verifier, provisioning, auditSink)
	attestationService.SetRevocationChecker(revocationChecker)
	attestationService.SetDeviceRegistry(deviceRegistry)
	handler := httpapi.New(log, provisioning, attestationService, cfg.MaxRequestBodyBytes, authVerifier)
	handler.SetDeviceRegistry(deviceRegistry)
	handler.SetObservability(metrics, tracerProvider.Tracer("provisioning/http"))
	production := cfg.Environment == "staging" || cfg.Environment == "production"
	timed := func(dependency, operation string, run readiness.CheckFunc) readiness.CheckFunc {
		return func(ctx context.Context) error {
			started := time.Now()
			err := run(ctx)
			metrics.RecordDependency(dependency, operation, started, err)
			return err
		}
	}
	readinessChecks := []readiness.Check{
		{Name: "rate_limiter", Required: production, Run: timed("redis", "ping", func(ctx context.Context) error {
			if redisClient == nil {
				return ratelimit.ErrUnavailable
			}
			return redisClient.Ping(ctx).Err()
		})},
		{Name: "authentication_jwks", Required: true, Run: timed("supabase_auth", "jwks_ready", authVerifier.Ready)},
		{Name: "attestation_provider_configuration", Required: production, Run: timed("attestation_provider", "configuration", func(context.Context) error {
			if cfg.AttestationProvider == "" {
				return attestation.ErrProviderReadiness
			}
			if _, unavailable := verifier.(attestation.UnavailableVerifier); unavailable {
				return attestation.ErrProviderReadiness
			}
			return nil
		})},
		{Name: "attestation_provider_health", Required: production, Run: timed("attestation_provider", "health", func(ctx context.Context) error {
			return attestation.ProviderReady(ctx, verifier)
		})},
	}
	if pool != nil {
		readinessChecks = append(readinessChecks,
			readiness.Check{Name: "database", Required: true, Run: pool.Ping},
			readiness.Check{Name: "database_migration", Required: true, Run: func(ctx context.Context) error {
				var applied bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 12)`).Scan(&applied); err != nil {
					return err
				}
				if !applied {
					return errors.New("required migration 012 is not applied")
				}
				return nil
			}},
		)
	} else {
		readinessChecks = append(readinessChecks,
			readiness.Check{Name: "database", Required: production, Run: func(context.Context) error {
				return errors.New("durable database is not configured")
			}},
			readiness.Check{Name: "database_migration", Required: production, Run: func(context.Context) error {
				return errors.New("durable database is not configured")
			}},
		)
	}
	handler.SetReadinessChecker(readiness.New(readinessChecks...))
	handler.SetRateLimiter(abuseLimiter, production)
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: handler.Routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
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
