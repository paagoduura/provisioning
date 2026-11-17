//go:build integration

package integration

import (
	"errors"
	"testing"

	"github.com/paagoduura/provisioning/migrations"
)

func TestMigrationChecksumsFreshInstallReplayAndDriftDetection(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	var rows, missing, malformed int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE checksum IS NULL), COUNT(*) FILTER (WHERE octet_length(checksum) <> 32) FROM schema_migrations`).Scan(&rows, &missing, &malformed); err != nil {
		t.Fatal(err)
	}
	if rows != 18 || missing != 0 || malformed != 0 {
		t.Fatalf("fresh migration ledger integrity: rows=%d missing=%d malformed=%d, want 18/0/0", rows, missing, malformed)
	}
	if err := migrations.Verify(ctx, pool); err != nil {
		t.Fatalf("verify a complete migration ledger: %v", err)
	}

	ledgerRows, err := pool.Query(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	for ledgerRows.Next() {
		var version int64
		var stored []byte
		if err := ledgerRows.Scan(&version, &stored); err != nil {
			ledgerRows.Close()
			t.Fatal(err)
		}
		expected, err := migrations.MigrationChecksum(version)
		if err != nil {
			ledgerRows.Close()
			t.Fatal(err)
		}
		if !equalBytes(stored, expected) {
			ledgerRows.Close()
			t.Fatalf("stored checksum for migration %03d differs from embedded file", version)
		}
	}
	if err := ledgerRows.Err(); err != nil {
		ledgerRows.Close()
		t.Fatal(err)
	}
	ledgerRows.Close()

	// A clean replay must validate every existing hash and perform no migration
	// SQL a second time.
	applyMigrations(t, ctx, pool)
	original, err := migrations.MigrationChecksum(18)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), original...)
	corrupt[0] ^= 0xff
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum = $1 WHERE version = 18`, corrupt); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool); !errors.Is(err, migrations.ErrMigrationDrift) {
		t.Fatalf("tampered ledger checksum error=%v, want ErrMigrationDrift", err)
	}
	if err := migrations.Verify(ctx, pool); !errors.Is(err, migrations.ErrMigrationDrift) {
		t.Fatalf("read-only verifier on tampered ledger error=%v, want ErrMigrationDrift", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum = $1 WHERE version = 18`, original); err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, ctx, pool)
}

func TestMigrationUpgradeAndExplicitLegacyChecksumBaseline(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)

	// Simulate a previously deployed ledger that predates checksum tracking.
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version BETWEEN 1 AND 11`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool); !errors.Is(err, migrations.ErrMigrationChecksumMissing) {
		t.Fatalf("unbaselined legacy history error=%v, want ErrMigrationChecksumMissing", err)
	}
	if err := migrations.BaselineLegacyChecksums(ctx, pool); err != nil {
		t.Fatalf("explicit legacy baseline: %v", err)
	}
	applyMigrations(t, ctx, pool)

	// Model a database at version 017 with prior checksums intact. The last
	// migration's indexes and ledger record are removed, then the runner applies
	// 018 forward and records its checksum.
	for _, index := range []string{
		"attestation_challenges_expiry_purge_idx",
		"interswitch_webhook_events_received_purge_idx",
		"audit_events_created_purge_idx",
		"provisioning_sessions_expiry_purge_idx",
		"attestation_challenges_session_expiry_idx",
		"interswitch_webhook_events_session_received_idx",
		"device_attestations_session_created_idx",
		"provisioning_retention_holds_active_scope_idx",
	} {
		if _, err := pool.Exec(ctx, `DROP INDEX `+pgxIdentifier(index)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `DROP TABLE provisioning_retention_holds`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 18`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Verify(ctx, pool); err == nil {
		t.Fatal("read-only verifier accepted a database missing migration 018")
	}
	applyMigrations(t, ctx, pool)
	if err := migrations.Verify(ctx, pool); err != nil {
		t.Fatalf("verify after forward upgrade: %v", err)
	}
	var checksum []byte
	if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version = 18`).Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	expected, err := migrations.MigrationChecksum(18)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(checksum, expected) {
		t.Fatal("forward-upgraded migration 018 checksum does not match embedded SQL")
	}
}

func TestMigrationFailureDoesNotRecordChecksumAndCanRecover(t *testing.T) {
	pool, ctx := openPostgres(t)
	// This deliberately malformed pre-existing object makes migration 001 fail
	// when it attempts to create an index over its expected device_uid_hash.
	if _, err := pool.Exec(ctx, `CREATE TABLE provisioning_sessions (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool); err == nil {
		t.Fatal("migration unexpectedly succeeded against the malformed schema")
	}
	var versionOneRows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&versionOneRows); err != nil {
		t.Fatal(err)
	}
	if versionOneRows != 0 {
		t.Fatalf("failed migration recorded %d ledger rows, want zero", versionOneRows)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE provisioning_sessions`); err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, ctx, pool)
	var checksum []byte
	if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version = 1`).Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	expected, err := migrations.MigrationChecksum(1)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(checksum, expected) {
		t.Fatal("recovered migration 001 checksum does not match embedded SQL")
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
