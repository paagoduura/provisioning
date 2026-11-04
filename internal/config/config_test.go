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
