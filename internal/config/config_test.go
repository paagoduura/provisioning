package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "")
	t.Setenv("SHUTDOWN_TIMEOUT_SECONDS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.MaxRequestBodyBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsUnsafeBodyLimit(t *testing.T) {
	t.Setenv("MAX_REQUEST_BODY_BYTES", "100")
	if _, err := Load(); err == nil {
		t.Fatal("expected body-limit validation error")
	}
}

func TestLoadRejectsStagingWithoutDatabase(t *testing.T) {
	t.Setenv("ENVIRONMENT", "staging")
	t.Setenv("DATABASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected staging database validation error")
	}
}

func TestLoadAllowsDevelopmentWithoutDatabase(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("DATABASE_URL", "")
	if _, err := Load(); err != nil {
		t.Fatalf("development should allow the in-memory repository: %v", err)
	}
}

func TestLoadReadsAppleConfiguration(t *testing.T) {
	t.Setenv("APPLE_APP_ID", "TEAM.example.app")
	t.Setenv("APPLE_APP_ATTEST_ENVIRONMENT", "sandbox")
	t.Setenv("APPLE_APP_ATTEST_ROOT_CERT_PEM", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppleAppID != "TEAM.example.app" || cfg.AppleEnvironment != "sandbox" || cfg.AppleRootCertificatePEM == "" {
		t.Fatalf("unexpected Apple configuration: %+v", cfg)
	}
}

func TestLoadReadsAndroidConfiguration(t *testing.T) {
	t.Setenv("ANDROID_PACKAGE_NAME", "com.example.provisioning")
	t.Setenv("ANDROID_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "123456789")
	t.Setenv("ANDROID_PLAY_INTEGRITY_MODE", "standard")
	t.Setenv("ANDROID_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS", "90")
	t.Setenv("ANDROID_PLAY_INTEGRITY_ALLOWED_DEVICE_VERDICTS", "MEETS_DEVICE_INTEGRITY,MEETS_BASIC_INTEGRITY")
	t.Setenv("ANDROID_PLAY_INTEGRITY_REQUIRE_LICENSED", "true")
	t.Setenv("ANDROID_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON", "{\"type\":\"service_account\"}")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AndroidPackageName != "com.example.provisioning" || cfg.AndroidCloudProject != 123456789 || cfg.AndroidMaxTokenAge.Seconds() != 90 || !cfg.AndroidRequireLicensed {
		t.Fatalf("unexpected Android configuration: %+v", cfg)
	}
}

func TestLoadRejectsPartialAndroidConfiguration(t *testing.T) {
	t.Setenv("ANDROID_PACKAGE_NAME", "com.example.provisioning")
	t.Setenv("ANDROID_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "")
	t.Setenv("ANDROID_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected partial Android configuration error")
	}
}

func TestLoadInfersKMSProviderFromKey(t *testing.T) {
	t.Setenv("ATTESTATION_PROVIDER", "")
	t.Setenv("AWS_KMS_KEY_ID", "key-1")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AttestationProvider != "aws-kms" {
		t.Fatalf("expected aws-kms provider, got %q", cfg.AttestationProvider)
	}
}

func TestLoadRejectsUnknownProvider(t *testing.T) {
	t.Setenv("ATTESTATION_PROVIDER", "unknown")
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown provider validation error")
	}
}

func TestLoadRequiresExplicitProviderInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("ATTESTATION_PROVIDER", "")
	t.Setenv("AWS_KMS_KEY_ID", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected production provider validation error")
	}
}

func TestLoadRequiresKMSKeyForKMSProvider(t *testing.T) {
	t.Setenv("ATTESTATION_PROVIDER", "aws-kms")
	t.Setenv("AWS_KMS_KEY_ID", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected KMS key validation error")
	}
}

func TestLoadRequiresOIDCInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("ATTESTATION_PROVIDER", "aws-kms")
	t.Setenv("AWS_KMS_KEY_ID", "key-1")
	t.Setenv("OIDC_ISSUER_URL", "")
	t.Setenv("OIDC_AUDIENCE", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected production OIDC configuration error")
	}
}

func TestLoadAcceptsGooglePlayCredentialsFile(t *testing.T) {
	t.Setenv("ATTESTATION_PROVIDER", "google-play-integrity")
	t.Setenv("GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME", "com.example.provisioning")
	t.Setenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON", "")
	t.Setenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE", `C:\secrets\play-integrity.json`)
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsPartialOIDCConfiguration(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://issuer.example")
	t.Setenv("OIDC_AUDIENCE", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected partial OIDC configuration error")
	}
}

func TestLoadRequiresOIDCWhenExplicitlyEnabled(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "")
	t.Setenv("OIDC_AUDIENCE", "")
	t.Setenv("OIDC_REQUIRED", "true")
	if _, err := Load(); err == nil {
		t.Fatal("expected required OIDC configuration error")
	}
}
