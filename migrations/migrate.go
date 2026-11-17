package migrations

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed *.sql
var files embed.FS

const migrationLockKey int64 = 0x50524f564953494f

var (
	ErrMigrationDrift           = errors.New("migration checksum drift detected")
	ErrMigrationChecksumMissing = errors.New("migration checksum baseline is missing")
	ErrUnknownMigrationVersion  = errors.New("database migration ledger contains an unknown version")
)

type migration struct {
	version  int64
	name     string
	sql      []byte
	checksum [sha256.Size]byte
}

// Apply applies unapplied SQL migrations in numeric order. Each migration and
// its checksum ledger entry commit atomically. Existing checksums are validated
// before any pending migration executes. A PostgreSQL advisory lock serializes
// concurrent runners across application replicas.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("migration pool is nil")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL connection for migrations: %w", err)
	}
	defer conn.Release()
	if err := lock(conn, ctx); err != nil {
		return err
	}
	defer unlock(conn)
	if err := ensureLedger(ctx, conn); err != nil {
		return err
	}
	available, err := embeddedMigrations()
	if err != nil {
		return err
	}
	applied, err := validateLedger(ctx, conn, available)
	if err != nil {
		return err
	}
	for _, item := range available {
		if _, ok := applied[item.version]; ok {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", item.name, err)
		}
		if _, err = tx.Exec(ctx, string(item.sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2) ON CONFLICT (version) DO UPDATE SET checksum = EXCLUDED.checksum`, item.version, item.checksum[:])
		}
		if err == nil {
			err = checksumNewLedgerRows(ctx, tx, available, applied)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", item.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", item.name, err)
		}
		applied[item.version] = item.checksum[:]
	}
	if _, err := validateLedger(ctx, conn, available); err != nil {
		return fmt.Errorf("validate migration ledger after apply: %w", err)
	}
	return nil
}

// Verify checks that every embedded migration is recorded and that every
// recorded checksum matches, without changing the database.
func Verify(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("migration pool is nil")
	}
	available, err := embeddedMigrations()
	if err != nil {
		return err
	}
	applied, err := validateLedger(ctx, pool, available)
	if err != nil {
		return err
	}
	for _, item := range available {
		if _, ok := applied[item.version]; !ok {
			return fmt.Errorf("required migration %03d (%s) is not applied", item.version, item.name)
		}
	}
	return nil
}

// checksumNewLedgerRows handles migrations such as 016 that intentionally
// backfill historical ledger versions using SQL. Only rows absent from the
// pre-migration validated ledger are eligible; pre-existing NULL checksums
// fail validation before migrations start and are never silently blessed.
func checksumNewLedgerRows(ctx context.Context, tx pgx.Tx, available []migration, previouslyApplied map[int64][]byte) error {
	byVersion := make(map[int64]migration, len(available))
	for _, item := range available {
		byVersion[item.version] = item
	}
	rows, err := tx.Query(ctx, `SELECT version FROM schema_migrations WHERE checksum IS NULL ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read newly-created migration ledger rows: %w", err)
	}
	var versions []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return fmt.Errorf("scan newly-created migration ledger row: %w", err)
		}
		if _, existed := previouslyApplied[version]; !existed {
			versions = append(versions, version)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate newly-created migration ledger rows: %w", err)
	}
	rows.Close()
	for _, version := range versions {
		item, ok := byVersion[version]
		if !ok {
			return fmt.Errorf("%w: %d", ErrUnknownMigrationVersion, version)
		}
		result, err := tx.Exec(ctx, `UPDATE schema_migrations SET checksum = $2 WHERE version = $1 AND checksum IS NULL`, version, item.checksum[:])
		if err != nil {
			return fmt.Errorf("record checksum for newly-created migration %03d: %w", version, err)
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("record checksum for newly-created migration %03d: ledger row changed unexpectedly", version)
		}
	}
	return nil
}

// BaselineLegacyChecksums explicitly records the current embedded-file hashes
// for already-applied ledger entries whose checksum is NULL. Call this only
// after an operator has verified that these exact migration files represent
// the database's historical schema. Existing non-NULL checksums are verified,
// never overwritten. The operation is serialized and all-or-nothing.
func BaselineLegacyChecksums(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("migration pool is nil")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL connection for checksum baseline: %w", err)
	}
	defer conn.Release()
	if err := lock(conn, ctx); err != nil {
		return err
	}
	defer unlock(conn)
	if err := ensureLedger(ctx, conn); err != nil {
		return err
	}
	available, err := embeddedMigrations()
	if err != nil {
		return err
	}
	byVersion := make(map[int64]migration, len(available))
	for _, item := range available {
		byVersion[item.version] = item
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin legacy checksum baseline: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version FOR UPDATE`)
	if err != nil {
		return fmt.Errorf("read legacy migration ledger: %w", err)
	}
	type ledgerRecord struct {
		version  int64
		checksum []byte
	}
	var records []ledgerRecord
	for rows.Next() {
		var record ledgerRecord
		if err := rows.Scan(&record.version, &record.checksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy migration ledger: %w", err)
		}
		record.checksum = append([]byte(nil), record.checksum...)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read legacy migration ledger rows: %w", err)
	}
	rows.Close()
	hasReadinessLedger := false
	for _, record := range records {
		if record.version == 12 {
			hasReadinessLedger = true
			break
		}
	}
	for _, record := range records {
		item, ok := byVersion[record.version]
		if !ok {
			return fmt.Errorf("%w: %d", ErrUnknownMigrationVersion, record.version)
		}
		if len(record.checksum) != 0 {
			if len(record.checksum) != sha256.Size || !equalChecksum(record.checksum, item.checksum[:]) {
				return fmt.Errorf("%w: migration %03d (%s)", ErrMigrationDrift, record.version, item.name)
			}
			continue
		}
		result, err := tx.Exec(ctx, `UPDATE schema_migrations SET checksum = $2 WHERE version = $1 AND checksum IS NULL`, record.version, item.checksum[:])
		if err != nil {
			return fmt.Errorf("baseline checksum for migration %03d: %w", record.version, err)
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("baseline checksum for migration %03d: ledger row changed concurrently", record.version)
		}
	}
	// Migration 012 was the first migration to create a ledger. Its successful
	// presence therefore proves only the validated pre-ledger deployment point;
	// versions 001–011 were historically not represented in that ledger. During
	// this explicitly operator-approved baseline, record those versions from the
	// reviewed embedded release instead of replaying potentially non-idempotent
	// DDL against an existing deployment.
	if hasReadinessLedger {
		for version := int64(1); version < 12; version++ {
			item := byVersion[version]
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`, version, item.checksum[:]); err != nil {
				return fmt.Errorf("record pre-ledger migration %03d during explicit legacy baseline: %w", version, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit legacy checksum baseline: %w", err)
	}
	return nil
}

// MigrationChecksum returns the SHA-256 checksum of an embedded migration.
func MigrationChecksum(version int64) ([]byte, error) {
	available, err := embeddedMigrations()
	if err != nil {
		return nil, err
	}
	for _, item := range available {
		if item.version == version {
			return append([]byte(nil), item.checksum[:]...), nil
		}
	}
	return nil, fmt.Errorf("%w: %d", ErrUnknownMigrationVersion, version)
}

func lock(conn *pgxpool.Conn, ctx context.Context) error {
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("lock migration runner: %w", err)
	}
	return nil
}

func unlock(conn *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationLockKey)
}

func ensureLedger(ctx context.Context, conn *pgxpool.Conn) error {
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now(), checksum BYTEA)`); err != nil {
		return fmt.Errorf("ensure migration ledger: %w", err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum BYTEA`); err != nil {
		return fmt.Errorf("add migration checksum column: %w", err)
	}
	const constraint = `DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'schema_migrations'::regclass
          AND conname = 'schema_migrations_checksum_length'
    ) THEN
        ALTER TABLE schema_migrations
            ADD CONSTRAINT schema_migrations_checksum_length
            CHECK (checksum IS NULL OR octet_length(checksum) = 32);
    END IF;
END
$migration$;`
	if _, err := conn.Exec(ctx, constraint); err != nil {
		return fmt.Errorf("ensure migration checksum constraint: %w", err)
	}
	return nil
}

func embeddedMigrations() ([]migration, error) {
	entries, err := fs.Glob(files, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	sort.Strings(entries)
	available := make([]migration, 0, len(entries))
	seen := make(map[int64]string, len(entries))
	for _, name := range entries {
		version, err := migrationVersion(name)
		if err != nil {
			return nil, err
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("duplicate migration version %03d in %q and %q", version, previous, name)
		}
		sql, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		seen[version] = name
		available = append(available, migration{version: version, name: name, sql: sql, checksum: sha256.Sum256(sql)})
	}
	return available, nil
}

type ledgerQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func validateLedger(ctx context.Context, querier ledgerQuerier, available []migration) (map[int64][]byte, error) {
	byVersion := make(map[int64]migration, len(available))
	for _, item := range available {
		byVersion[item.version] = item
	}
	rows, err := querier.Query(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read migration ledger for validation: %w", err)
	}
	defer rows.Close()
	applied := make(map[int64][]byte)
	for rows.Next() {
		var version int64
		var checksum []byte
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan migration ledger: %w", err)
		}
		item, ok := byVersion[version]
		if !ok {
			return nil, fmt.Errorf("%w: %d", ErrUnknownMigrationVersion, version)
		}
		if len(checksum) == 0 {
			return nil, fmt.Errorf("%w: migration %03d (%s); explicitly baseline after verifying the deployed migration files", ErrMigrationChecksumMissing, version, item.name)
		}
		if len(checksum) != sha256.Size || !equalChecksum(checksum, item.checksum[:]) {
			return nil, fmt.Errorf("%w: migration %03d (%s)", ErrMigrationDrift, version, item.name)
		}
		applied[version] = append([]byte(nil), checksum...)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration ledger: %w", err)
	}
	return applied, nil
}

func equalChecksum(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for index := range a {
		difference |= a[index] ^ b[index]
	}
	return difference == 0
}

func migrationVersion(name string) (int64, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok || len(prefix) != 3 {
		return 0, fmt.Errorf("migration filename %q must begin with a three-digit version and underscore", name)
	}
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("migration filename %q has an invalid version", name)
	}
	return version, nil
}
