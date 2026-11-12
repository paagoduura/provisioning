package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr                  string
	Environment               string
	LogLevel                  string
	DatabaseURL               string
	RedisURL                  string
	SupabaseAuthIssuer        string
	SupabaseAuthAudience      string
	AttestationProvider       string
	GooglePlayPackageName     string
	GooglePlayCredentials     string
	GooglePlayCredentialsFile string
	GooglePlayRequireLicensed bool
	AWSRegion                 string
	AWSKMSKeyID               string
	AWSKMSSigningAlgorithm    string
	AppleTeamID               string
	AppleBundleID             string
	AppleEnvironment          string
	AppleRootCertificateFile  string
	MaxRequestBodyBytes       int64
	ShutdownTimeout           time.Duration
}

func Load() (Config, error) {
	maxBody, err := int64Env("MAX_REQUEST_BODY_BYTES", 1<<20)
	if err != nil {
		return Config{}, err
	}
	shutdownSeconds, err := int64Env("SHUTDOWN_TIMEOUT_SECONDS", 10)
	if err != nil || shutdownSeconds < 1 {
		return Config{}, errors.New("SHUTDOWN_TIMEOUT_SECONDS must be a positive integer")
	}
	provider := getenv("ATTESTATION_PROVIDER", "")
	if provider == "" && os.Getenv("AWS_KMS_KEY_ID") != "" {
		provider = "aws-kms"
	}
	cfg := Config{HTTPAddr: getenv("HTTP_ADDR", ":8080"), Environment: getenv("ENVIRONMENT", "development"), LogLevel: getenv("LOG_LEVEL", "info"), DatabaseURL: os.Getenv("DATABASE_URL"), RedisURL: os.Getenv("REDIS_URL"), SupabaseAuthIssuer: getenv("SUPABASE_AUTH_ISSUER", "https://haytetewtgbfxnolrhjz.supabase.co/auth/v1"), SupabaseAuthAudience: getenv("SUPABASE_AUTH_AUDIENCE", "authenticated"), AttestationProvider: provider, GooglePlayPackageName: os.Getenv("GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME"), GooglePlayCredentials: os.Getenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON"), GooglePlayCredentialsFile: os.Getenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE"), GooglePlayRequireLicensed: getenv("GOOGLE_PLAY_INTEGRITY_REQUIRE_LICENSED", "true") == "true", AWSRegion: getenv("AWS_REGION", "eu-north-1"), AWSKMSKeyID: os.Getenv("AWS_KMS_KEY_ID"), AWSKMSSigningAlgorithm: getenv("AWS_KMS_SIGNING_ALGORITHM", "RSASSA_PKCS1_V1_5_SHA_256"), AppleTeamID: os.Getenv("APPLE_TEAM_ID"), AppleBundleID: os.Getenv("APPLE_BUNDLE_ID"), AppleEnvironment: getenv("APPLE_APP_ATTEST_ENVIRONMENT", "production"), AppleRootCertificateFile: os.Getenv("APPLE_APP_ATTEST_ROOT_CERT_FILE"), MaxRequestBodyBytes: maxBody, ShutdownTimeout: time.Duration(shutdownSeconds) * time.Second}
	if cfg.HTTPAddr == "" {
		return Config{}, errors.New("HTTP_ADDR must not be empty")
	}
	if cfg.SupabaseAuthIssuer == "" || cfg.SupabaseAuthAudience == "" {
		return Config{}, errors.New("SUPABASE_AUTH_ISSUER and SUPABASE_AUTH_AUDIENCE must not be empty")
	}
	if (cfg.Environment == "staging" || cfg.Environment == "production") && cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required for staging and production")
	}
	if (cfg.Environment == "staging" || cfg.Environment == "production") && cfg.RedisURL == "" {
		return Config{}, errors.New("REDIS_URL is required for staging and production rate limiting")
	}
	if cfg.MaxRequestBodyBytes < 1024 {
		return Config{}, errors.New("MAX_REQUEST_BODY_BYTES must be at least 1024")
	}
	if cfg.AWSRegion == "" {
		return Config{}, errors.New("AWS_REGION must not be empty")
	}
	switch cfg.AttestationProvider {
	case "", "aws-kms", "apple-app-attest", "google-play-integrity", "cloudhsm-pkcs11":
	default:
		return Config{}, errors.New("ATTESTATION_PROVIDER must be one of aws-kms, apple-app-attest, google-play-integrity, cloudhsm-pkcs11")
	}
	if (cfg.Environment == "staging" || cfg.Environment == "production") && cfg.AttestationProvider == "" {
		return Config{}, errors.New("ATTESTATION_PROVIDER is required for staging and production")
	}
	if cfg.AttestationProvider == "aws-kms" && cfg.AWSKMSKeyID == "" {
		return Config{}, errors.New("AWS_KMS_KEY_ID is required when ATTESTATION_PROVIDER=aws-kms")
	}
	if cfg.AttestationProvider == "google-play-integrity" && (cfg.GooglePlayPackageName == "" || (cfg.GooglePlayCredentials == "" && cfg.GooglePlayCredentialsFile == "")) {
		return Config{}, errors.New("GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME and either GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE or GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON are required when ATTESTATION_PROVIDER=google-play-integrity")
	}
	if cfg.AttestationProvider == "apple-app-attest" && (cfg.AppleTeamID == "" || cfg.AppleBundleID == "" || cfg.AppleRootCertificateFile == "" || (cfg.AppleEnvironment != "development" && cfg.AppleEnvironment != "production")) {
		return Config{}, errors.New("APPLE_TEAM_ID, APPLE_BUNDLE_ID, APPLE_APP_ATTEST_ROOT_CERT_FILE, and APPLE_APP_ATTEST_ENVIRONMENT=development|production are required when ATTESTATION_PROVIDER=apple-app-attest")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func int64Env(key string, fallback int64) (int64, error) {
	v := getenv(key, strconv.FormatInt(fallback, 10))
	return strconv.ParseInt(v, 10, 64)
}
