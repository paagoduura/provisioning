package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "")
	t.Setenv("SHUTDOWN_TIMEOUT_SECONDS", "")
	t.Setenv("AUTO_MIGRATE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.MaxRequestBodyBytes != 1<<20 || cfg.SupabaseAuthIssuer != "https://haytetewtgbfxnolrhjz.supabase.co/auth/v1" || cfg.SupabaseAuthAudience != "authenticated" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestAutoMigrateRequiresDatabase(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "true")
	t.Setenv("DATABASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected AUTO_MIGRATE to require DATABASE_URL")
	}
}

func TestAutoMigrateIsRejectedOutsideDevelopment(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "true")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("ENVIRONMENT", "production")
	if _, err := Load(); err == nil {
		t.Fatal("expected AUTO_MIGRATE to be rejected in production")
	}
}

func TestAutoMigrateCanBeExplicitlyEnabledInDevelopment(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "true")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("ENVIRONMENT", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoMigrate {
		t.Fatal("expected AUTO_MIGRATE=true to be enabled")
	}
}

func TestAutoMigrateRejectsInvalidValue(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid AUTO_MIGRATE value to be rejected")
	}
}

func TestInterswitchIdempotencySupportIsOptIn(t *testing.T) {
	t.Setenv("INTERSWITCH_SUPPORTS_IDEMPOTENCY_KEY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InterswitchIdempotencyKeySupported {
		t.Fatal("provider idempotency header must remain disabled unless explicitly confirmed")
	}
	t.Setenv("INTERSWITCH_SUPPORTS_IDEMPOTENCY_KEY", "true")
	cfg, err = Load()
	if err != nil || !cfg.InterswitchIdempotencyKeySupported {
		t.Fatalf("explicit provider idempotency support was not enabled: cfg=%+v err=%v", cfg, err)
	}
	t.Setenv("INTERSWITCH_SUPPORTS_IDEMPOTENCY_KEY", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("invalid provider idempotency support value should fail closed")
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
	setValidStagingEnv(t)
	t.Setenv("REDIS_URL", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REDIS_URL") {
		t.Fatal("expected staging to require REDIS_URL")
	}
}

func TestStagingRequiresAllInterSwitchSettings(t *testing.T) {
	for _, name := range []string{
		"INTERSWITCH_TOKEN_URL",
		"INTERSWITCH_REQUEST_URL",
		"INTERSWITCH_CLIENT_ID",
		"INTERSWITCH_CLIENT_SECRET",
		"INTERSWITCH_WEBHOOK_SECRET",
	} {
		t.Run(name, func(t *testing.T) {
			setValidStagingEnv(t)
			t.Setenv(name, "")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Load error = %v, want required-setting error naming %s", err, name)
			}
		})
	}
}

func TestCompleteStagingConfigAcceptsInferredKMSProvider(t *testing.T) {
	setValidStagingEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AttestationProvider != "aws-kms" {
		t.Fatalf("attestation provider = %q, want aws-kms inferred from AWS_KMS_KEY_ID", cfg.AttestationProvider)
	}
}

func TestStagingRejectsMalformedRedisURL(t *testing.T) {
	setValidStagingEnv(t)
	t.Setenv("REDIS_URL", "https://redis.example.invalid")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REDIS_URL") {
		t.Fatalf("Load error = %v, want invalid REDIS_URL failure", err)
	}
}

func setValidStagingEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENVIRONMENT", "staging")
	t.Setenv("DATABASE_URL", "postgresql://staging-user:secret@postgres.example.invalid:5432/provisioning?sslmode=require")
	t.Setenv("REDIS_URL", "rediss://staging-user:secret@redis.example.invalid:6379/0")
	t.Setenv("INTERSWITCH_TOKEN_URL", "https://api.example.invalid/oauth/token")
	t.Setenv("INTERSWITCH_REQUEST_URL", "https://api.example.invalid/token/request")
	t.Setenv("INTERSWITCH_CLIENT_ID", "staging-client")
	t.Setenv("INTERSWITCH_CLIENT_SECRET", "staging-client-secret")
	t.Setenv("INTERSWITCH_WEBHOOK_SECRET", "staging-webhook-secret")
	t.Setenv("ATTESTATION_PROVIDER", "")
	t.Setenv("AWS_KMS_KEY_ID", "arn:aws:kms:eu-north-1:123456789012:key/11111111-2222-3333-4444-555555555555")
	t.Setenv("AUTO_MIGRATE", "false")
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
