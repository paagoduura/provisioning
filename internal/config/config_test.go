package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "")
	t.Setenv("SHUTDOWN_TIMEOUT_SECONDS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.MaxRequestBodyBytes != 1<<20 || cfg.SupabaseAuthIssuer != "https://haytetewtgbfxnolrhjz.supabase.co/auth/v1" || cfg.SupabaseAuthAudience != "authenticated" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsUnsafeBodyLimit(t *testing.T) {
	t.Setenv("MAX_REQUEST_BODY_BYTES", "100")
	if _, err := Load(); err == nil {
		t.Fatal("expected body-limit validation error")
	}
}

func TestLoadRejectsEphemeralPersistenceOutsideDevelopment(t *testing.T) {
	t.Setenv("ENVIRONMENT", "staging")
	t.Setenv("DATABASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected staging to require DATABASE_URL")
	}
}

func TestLoadRequiresRedisOutsideDevelopment(t *testing.T) {
	t.Setenv("ENVIRONMENT", "staging")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("REDIS_URL", "")
	t.Setenv("ATTESTATION_PROVIDER", "aws-kms")
	t.Setenv("AWS_KMS_KEY_ID", "key-1")
	if _, err := Load(); err == nil {
		t.Fatal("expected staging to require REDIS_URL")
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

func TestLoadAcceptsGooglePlayCredentialsFile(t *testing.T) {
	t.Setenv("ATTESTATION_PROVIDER", "google-play-integrity")
	t.Setenv("GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME", "com.duuratech.pay")
	t.Setenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON", "")
	t.Setenv("GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE", "C:\\secrets\\play-integrity.json")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
