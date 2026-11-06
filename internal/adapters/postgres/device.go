package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/domain"
)

// DeviceRepository stores the device registry in PostgreSQL. Device identity
// hashes are persisted, while raw device identifiers are never accepted here.
type DeviceRepository struct {
	pool *pgxpool.Pool
}

var _ domain.DeviceRepository = (*DeviceRepository)(nil)

func NewDeviceRepository(pool *pgxpool.Pool) *DeviceRepository {
	return &DeviceRepository{pool: pool}
}

func (r *DeviceRepository) Create(ctx context.Context, device domain.Device) error {
	if err := device.Validate(); err != nil {
		return fmt.Errorf("validate device: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device create: %w", err)
	}
	defer tx.Rollback(ctx) // harmless after commit

	_, err = tx.Exec(ctx, `
		INSERT INTO registered_devices
		    (id, owner_id, device_identity_hash, model, transport, state,
		     created_at, updated_at, suspended_at, revoked_at, retired_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		device.ID, device.OwnerID, device.DeviceIdentityHash, device.Model,
		device.Transport, device.State, device.CreatedAt, device.UpdatedAt,
		device.SuspendedAt, device.RevokedAt, device.RetiredAt)
	if err != nil {
		return fmt.Errorf("create device: %w", err)
	}
	if err := insertDeviceAttestations(ctx, tx, device); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit device create: %w", err)
	}
	return nil
}

func (r *DeviceRepository) Get(ctx context.Context, id string) (domain.Device, error) {
	device, err := scanDevice(ctx, r.pool, id)
	if err != nil {
		return domain.Device{}, err
	}
	rows, err := r.pool.Query(ctx, `
		SELECT provider, key_id, trust_level, counter, first_seen_at,
		       last_seen_at, revoked_at, revocation_reason
		FROM registered_device_attestations
		WHERE device_id = $1
		ORDER BY id`, id)
	if err != nil {
		return domain.Device{}, fmt.Errorf("get device attestations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var attestation domain.DeviceAttestation
		if err := rows.Scan(&attestation.Provider, &attestation.KeyID,
			&attestation.TrustLevel, &attestation.Counter,
			&attestation.FirstSeenAt, &attestation.LastSeenAt,
			&attestation.RevokedAt, &attestation.RevocationReason); err != nil {
			return domain.Device{}, fmt.Errorf("scan device attestation: %w", err)
		}
		device.Attestations = append(device.Attestations, attestation)
	}
	if err := rows.Err(); err != nil {
		return domain.Device{}, fmt.Errorf("iterate device attestations: %w", err)
	}
	if err := device.Validate(); err != nil {
		return domain.Device{}, fmt.Errorf("validate persisted device: %w", err)
	}
	return device, nil
}

func (r *DeviceRepository) Save(ctx context.Context, device domain.Device) error {
	if err := device.Validate(); err != nil {
		return fmt.Errorf("validate device: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device save: %w", err)
	}
	defer tx.Rollback(ctx)

	result, err := tx.Exec(ctx, `
		UPDATE registered_devices
		SET owner_id = $2, device_identity_hash = $3, model = $4,
		    transport = $5, state = $6, updated_at = $7,
		    suspended_at = $8, revoked_at = $9, retired_at = $10
		WHERE id = $1`, device.ID, device.OwnerID, device.DeviceIdentityHash,
		device.Model, device.Transport, device.State, device.UpdatedAt,
		device.SuspendedAt, device.RevokedAt, device.RetiredAt)
	if err != nil {
		return fmt.Errorf("save device: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrDeviceNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM registered_device_attestations WHERE device_id = $1`, device.ID); err != nil {
		return fmt.Errorf("replace device attestations: %w", err)
	}
	if err := insertDeviceAttestations(ctx, tx, device); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit device save: %w", err)
	}
	return nil
}

var ErrDeviceNotFound = errors.New("device not found")

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scanDevice(ctx context.Context, q queryer, id string) (domain.Device, error) {
	var device domain.Device
	err := q.QueryRow(ctx, `
		SELECT id, owner_id, device_identity_hash, model, transport, state,
		       created_at, updated_at, suspended_at, revoked_at, retired_at
		FROM registered_devices WHERE id = $1`, id).Scan(
		&device.ID, &device.OwnerID, &device.DeviceIdentityHash, &device.Model,
		&device.Transport, &device.State, &device.CreatedAt, &device.UpdatedAt,
		&device.SuspendedAt, &device.RevokedAt, &device.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return domain.Device{}, fmt.Errorf("get device: %w", err)
	}
	return device, nil
}

func insertDeviceAttestations(ctx context.Context, tx pgx.Tx, device domain.Device) error {
	for _, attestation := range device.Attestations {
		_, err := tx.Exec(ctx, `
			INSERT INTO registered_device_attestations
			    (device_id, provider, key_id, trust_level, counter,
			     first_seen_at, last_seen_at, revoked_at, revocation_reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''))`,
			device.ID, attestation.Provider, attestation.KeyID,
			attestation.TrustLevel, attestation.Counter, attestation.FirstSeenAt,
			attestation.LastSeenAt, attestation.RevokedAt, attestation.RevocationReason)
		if err != nil {
			return fmt.Errorf("save device attestation: %w", err)
		}
	}
	return nil
}
