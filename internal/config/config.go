package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr               string
	Environment            string
	LogLevel               string
	DatabaseURL            string
	AttestationProvider    string
	AWSRegion              string
	AWSKMSKeyID            string
	AWSKMSSigningAlgorithm string
	MaxRequestBodyBytes    int64
	ShutdownTimeout        time.Duration
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
	cfg := Config{HTTPAddr: getenv("HTTP_ADDR", ":8080"), Environment: getenv("ENVIRONMENT", "development"), LogLevel: getenv("LOG_LEVEL", "info"), DatabaseURL: os.Getenv("DATABASE_URL"), AttestationProvider: provider, AWSRegion: getenv("AWS_REGION", "eu-north-1"), AWSKMSKeyID: os.Getenv("AWS_KMS_KEY_ID"), AWSKMSSigningAlgorithm: getenv("AWS_KMS_SIGNING_ALGORITHM", "RSASSA_PKCS1_V1_5_SHA_256"), MaxRequestBodyBytes: maxBody, ShutdownTimeout: time.Duration(shutdownSeconds) * time.Second}
	if cfg.HTTPAddr == "" {
		return Config{}, errors.New("HTTP_ADDR must not be empty")
	}
	if (cfg.Environment == "staging" || cfg.Environment == "production") && cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required for staging and production")
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
