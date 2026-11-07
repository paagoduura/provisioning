package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	"golang.org/x/oauth2/google"
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
	var deviceRegistry *service.DeviceService
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
		deviceRegistry = service.NewDeviceService(postgresadapter.NewDeviceRepository(pool))
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
	verifiers := attestation.ProviderRouter{}
	providerEnabled := func(provider string) bool {
		return cfg.AttestationProvider == "" || cfg.AttestationProvider == provider
	}
	if cfg.AWSKMSKeyID != "" && providerEnabled(attestation.KMSProvider) {
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
		verifiers[attestation.KMSProvider] = attestation.KMSVerifier{Client: kms.NewFromConfig(awsConfig), KeyID: cfg.AWSKMSKeyID, Algorithm: algorithm}
		log.Info("attestation_verifier_selected", "provider", attestation.KMSProvider, "region", cfg.AWSRegion)
	}
	if cfg.GooglePlayPackageName != "" && providerEnabled(attestation.GooglePlayIntegrityProvider) {
		credentials := []byte(cfg.GooglePlayCredentials)
		if cfg.GooglePlayCredentialsFile != "" {
			var readErr error
			credentials, readErr = os.ReadFile(cfg.GooglePlayCredentialsFile)
			if readErr != nil {
				log.Error("google_play_credentials_failed", "error", readErr)
				os.Exit(1)
			}
		}
		verifiers[attestation.GooglePlayIntegrityProvider] = attestation.GooglePlayIntegrityVerifier{
			Client: http.DefaultClient, CredentialsJSON: credentials, PackageName: cfg.GooglePlayPackageName,
			RequireLicensed: cfg.GooglePlayRequireLicensed, MaxTokenAge: 5 * time.Minute, MaxClockSkew: 30 * time.Second,
		}
		log.Info("attestation_verifier_selected", "provider", attestation.GooglePlayIntegrityProvider, "package_name", cfg.GooglePlayPackageName)
	}
	if (cfg.AppleAppID != "" || cfg.AppleRootCertificate != "" || cfg.AppleRootCertificatePEM != "") && providerEnabled(attestation.AppleAppAttestProvider) {
		if cfg.AppleAppID == "" || (cfg.AppleRootCertificate == "" && cfg.AppleRootCertificatePEM == "") || (cfg.AppleRootCertificate != "" && cfg.AppleRootCertificatePEM != "") {
			log.Error("apple_app_attest_config_failed", "error", "APPLE_APP_ID and exactly one of APPLE_APP_ATTEST_ROOT_CERT_FILE or APPLE_APP_ATTEST_ROOT_CERT_PEM must be configured")
			os.Exit(1)
		}
		rootPEM := []byte(cfg.AppleRootCertificatePEM)
		if cfg.AppleRootCertificate != "" {
			var readErr error
			rootPEM, readErr = os.ReadFile(cfg.AppleRootCertificate)
			if readErr != nil {
				log.Error("apple_app_attest_config_failed", "error", readErr)
				os.Exit(1)
			}
		}
		root, rootErr := attestation.LoadAppleRootCertificatePEM(rootPEM)
		if rootErr != nil {
			log.Error("apple_app_attest_config_failed", "error", rootErr)
			os.Exit(1)
		}
		var appleKeys attestation.AppleKeyStore
		if pool != nil {
			appleKeys = postgresadapter.NewAppleAppAttestKeyStore(pool)
		} else {
			appleKeys = attestation.NewMemoryAppleKeyStore()
		}
		verifiers[attestation.AppleAppAttestProvider] = attestation.AppleAppAttestVerifier{AppID: cfg.AppleAppID, Environment: cfg.AppleEnvironment, AppleRoot: root, Keys: appleKeys}
		log.Info("attestation_verifier_selected", "provider", attestation.AppleAppAttestProvider, "environment", cfg.AppleEnvironment)
	}
	if (cfg.AndroidPackageName != "" || cfg.AndroidCloudProject != 0 || cfg.AndroidServiceAccount != "") && providerEnabled(attestation.AndroidPlayIntegrityProvider) {
		oauthConfig, oauthErr := google.JWTConfigFromJSON([]byte(cfg.AndroidServiceAccount), "https://www.googleapis.com/auth/playintegrity")
		if oauthErr != nil {
			log.Error("android_play_integrity_config_failed", "error", oauthErr)
			os.Exit(1)
		}
		allowed := make(map[string]struct{})
		for _, verdict := range strings.Split(cfg.AndroidAllowedVerdicts, ",") {
			if verdict = strings.TrimSpace(verdict); verdict != "" {
				allowed[verdict] = struct{}{}
			}
		}
		verifiers[attestation.AndroidPlayIntegrityProvider] = attestation.AndroidPlayIntegrityVerifier{
			PackageName:           cfg.AndroidPackageName,
			CloudProjectNumber:    cfg.AndroidCloudProject,
			Mode:                  attestation.PlayIntegrityMode(cfg.AndroidMode),
			MaxTokenAge:           cfg.AndroidMaxTokenAge,
			RequireLicensed:       cfg.AndroidRequireLicensed,
			AllowedDeviceVerdicts: allowed,
			Decoder:               attestation.GooglePlayIntegrityClient{PackageName: cfg.AndroidPackageName, TokenSource: oauthConfig.TokenSource(context.Background())},
		}
		log.Info("attestation_verifier_selected", "provider", attestation.AndroidPlayIntegrityProvider, "package_name", cfg.AndroidPackageName, "mode", cfg.AndroidMode, "cloud_project_configured", true)
	}
	if len(verifiers) == 0 {
		log.Warn("attestation_verifier_selected", "provider", "unavailable", "warning", "configure AWS KMS or Apple App Attest before production use")
	}
	attestationService := attestation.New(attestationRepo, attestationRecords, verifiers, provisioning, auditSink)
	attestationService.SetRevocationChecker(revocationChecker)
	if deviceRegistry != nil {
		attestationService.SetDeviceRegistry(deviceRegistry)
	}
	handler := httpapi.New(log, provisioning, attestationService, cfg.MaxRequestBodyBytes)
	handler.SetDeviceRegistry(deviceRegistry)
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
