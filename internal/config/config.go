package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr                  string
	Environment               string
	LogLevel                  string
	DatabaseURL               string
	AttestationProvider       string
	GooglePlayPackageName     string
	GooglePlayCredentials     string
	GooglePlayCredentialsFile string
	GooglePlayRequireLicensed bool
	AWSRegion                 string
	AWSKMSKeyID               string
	AWSKMSSigningAlgorithm    string
	AppleAppID                string
	AppleEnvironment          string
	AppleRootCertificate      string
	AppleRootCertificatePEM   string
	AndroidPackageName        string
	AndroidCloudProject       uint64
	AndroidMode               string
	AndroidMaxTokenAge        time.Duration
	AndroidAllowedVerdicts    string
	AndroidRequireLicensed    bool
	AndroidServiceAccount     string
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
	androidProject, err := uint64Env("ANDROID_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", 0)
	if err != nil {
		return Config{}, err
	}
	androidMaxAgeSeconds, err := int64Env("ANDROID_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS", 120)
	if err != nil || androidMaxAgeSeconds < 1 {
		return Config{}, errors.New("ANDROID_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS must be a positive integer")
	}
	androidRequireLicensed, err := strconv.ParseBool(getenv("ANDROID_PLAY_INTEGRITY_REQUIRE_LICENSED", "true"))
	if err != nil {
		return Config{}, errors.New("ANDROID_PLAY_INTEGRITY_REQUIRE_LICENSED must be true or false")
	}
	provider := strings.TrimSpace(os.Getenv("ATTESTATION_PROVIDER"))
	if provider == "" && os.Getenv("AWS_KMS_KEY_ID") != "" {
		provider = "aws-kms"
	}
	cfg := Config{
		HTTPAddr: getenv("HTTP_ADDR", ":8080"), Environment: getenv("ENVIRONMENT", "development"), LogLevel: getenv("LOG_LEVEL", "info"), DatabaseURL: os.Getenv("DATABASE_URL"),
		AttestationProvider: provider, GooglePlayPackageName: os.Getenv("GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME"), GooglePlayCredentials: os.Getenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON"), GooglePlayCredentialsFile: os.Getenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE"), GooglePlayRequireLicensed: getenv("GOOGLE_PLAY_INTEGRITY_REQUIRE_LICENSED", "true") == "true",
		AWSRegion: getenv("AWS_REGION", "eu-north-1"), AWSKMSKeyID: os.Getenv("AWS_KMS_KEY_ID"), AWSKMSSigningAlgorithm: getenv("AWS_KMS_SIGNING_ALGORITHM", "RSASSA_PKCS1_V1_5_SHA_256"),
		AppleAppID: os.Getenv("APPLE_APP_ID"), AppleEnvironment: getenv("APPLE_APP_ATTEST_ENVIRONMENT", "production"), AppleRootCertificate: os.Getenv("APPLE_APP_ATTEST_ROOT_CERT_FILE"), AppleRootCertificatePEM: os.Getenv("APPLE_APP_ATTEST_ROOT_CERT_PEM"),
		AndroidPackageName: os.Getenv("ANDROID_PACKAGE_NAME"), AndroidCloudProject: androidProject, AndroidMode: getenv("ANDROID_PLAY_INTEGRITY_MODE", "standard"), AndroidMaxTokenAge: time.Duration(androidMaxAgeSeconds) * time.Second, AndroidAllowedVerdicts: getenv("ANDROID_PLAY_INTEGRITY_ALLOWED_DEVICE_VERDICTS", "MEETS_DEVICE_INTEGRITY"), AndroidRequireLicensed: androidRequireLicensed, AndroidServiceAccount: os.Getenv("ANDROID_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON"),
		MaxRequestBodyBytes: maxBody, ShutdownTimeout: time.Duration(shutdownSeconds) * time.Second,
	}
	if cfg.HTTPAddr == "" {
		return Config{}, errors.New("HTTP_ADDR must not be empty")
	}
	if (strings.EqualFold(cfg.Environment, "staging") || strings.EqualFold(cfg.Environment, "production")) && strings.TrimSpace(cfg.DatabaseURL) == "" {
		return Config{}, errors.New("DATABASE_URL is required for staging and production")
	}
	if cfg.MaxRequestBodyBytes < 1024 {
		return Config{}, errors.New("MAX_REQUEST_BODY_BYTES must be at least 1024")
	}
	if cfg.AWSRegion == "" {
		return Config{}, errors.New("AWS_REGION must not be empty")
	}
	switch cfg.AttestationProvider {
	case "", "aws-kms", "apple-app-attest", "google-play-integrity", "android-play-integrity", "cloudhsm-pkcs11":
	default:
		return Config{}, errors.New("ATTESTATION_PROVIDER is not a supported provider")
	}
	if (strings.EqualFold(cfg.Environment, "staging") || strings.EqualFold(cfg.Environment, "production")) && cfg.AttestationProvider == "" {
		return Config{}, errors.New("ATTESTATION_PROVIDER is required for staging and production")
	}
	if cfg.AttestationProvider == "aws-kms" && cfg.AWSKMSKeyID == "" {
		return Config{}, errors.New("AWS_KMS_KEY_ID is required when ATTESTATION_PROVIDER=aws-kms")
	}
	if cfg.AttestationProvider == "google-play-integrity" && (cfg.GooglePlayPackageName == "" || (cfg.GooglePlayCredentials == "" && cfg.GooglePlayCredentialsFile == "")) {
		return Config{}, errors.New("GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME and either GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE or GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON are required when ATTESTATION_PROVIDER=google-play-integrity")
	}
	if cfg.AttestationProvider == "android-play-integrity" || cfg.AndroidPackageName != "" || cfg.AndroidCloudProject != 0 || cfg.AndroidServiceAccount != "" {
		if cfg.AttestationProvider == "android-play-integrity" && (cfg.AndroidPackageName == "" || cfg.AndroidCloudProject == 0 || cfg.AndroidServiceAccount == "") {
			return Config{}, errors.New("Android Play Integrity configuration is incomplete")
		}
		if cfg.AndroidPackageName != "" || cfg.AndroidCloudProject != 0 || cfg.AndroidServiceAccount != "" {
			if cfg.AndroidPackageName == "" || cfg.AndroidCloudProject == 0 || cfg.AndroidServiceAccount == "" {
				return Config{}, errors.New("ANDROID_PACKAGE_NAME, ANDROID_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER, and ANDROID_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON must be configured together")
			}
			if cfg.AndroidMode != "standard" && cfg.AndroidMode != "classic" {
				return Config{}, errors.New("ANDROID_PLAY_INTEGRITY_MODE must be standard or classic")
			}
		}
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

func uint64Env(key string, fallback uint64) (uint64, error) {
	v := getenv(key, strconv.FormatUint(fallback, 10))
	return strconv.ParseUint(v, 10, 64)
}
