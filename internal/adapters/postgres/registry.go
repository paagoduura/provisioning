package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/registry"
)

type DeviceRegistry struct{ pool *pgxpool.Pool }

func NewDeviceRegistry(pool *pgxpool.Pool) *DeviceRegistry { return &DeviceRegistry{pool: pool} }

func (r *DeviceRegistry) EnsureDevice(ctx context.Context, userID, deviceUID, model, transport string, now time.Time) (registry.Device, error) {
	uidHash := hashDeviceUID(deviceUID)
	var device registry.Device
	var state string
	var revokedAt *time.Time
	var replacedBy *string
	err := r.pool.QueryRow(ctx, `SELECT id, user_id, device_model, transport, lifecycle_state, created_at, updated_at, revoked_at, replaced_by_id FROM registered_devices WHERE device_uid_hash = $1`, uidHash).Scan(&device.ID, &device.UserID, &device.DeviceModel, &device.Transport, &state, &device.CreatedAt, &device.UpdatedAt, &revokedAt, &replacedBy)
	if err == nil {
		if device.UserID != userID {
			return registry.Device{}, registry.ErrDeviceAlreadyOwned
		}
		device.DeviceUID = deviceUID
		device.State = registry.LifecycleState(state)
		device.RevokedAt = revokedAt
		if replacedBy != nil {
			device.ReplacedByID = *replacedBy
		}
		return device, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return registry.Device{}, fmt.Errorf("find registered device: %w", err)
	}
	id, err := newDeviceID()
	if err != nil {
		return registry.Device{}, err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO registered_devices (id, user_id, device_uid_hash, device_model, transport, lifecycle_state, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`, id, userID, uidHash, model, transport, registry.StatePending, now)
	if err != nil {
		return registry.Device{}, fmt.Errorf("register device: %w", err)
	}
	return registry.Device{ID: id, UserID: userID, DeviceUID: deviceUID, DeviceModel: model, Transport: transport, State: registry.StatePending, CreatedAt: now, UpdatedAt: now}, nil
}

func (r *DeviceRegistry) GetDevice(ctx context.Context, userID, deviceID string) (registry.Device, error) {
	return r.getOwnedDevice(ctx, userID, deviceID)
}

func (r *DeviceRegistry) ListDevices(ctx context.Context, userID string) ([]registry.Device, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, user_id, device_model, transport, lifecycle_state, created_at, updated_at, revoked_at, replaced_by_id FROM registered_devices WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list registered devices: %w", err)
	}
	defer rows.Close()
	result := make([]registry.Device, 0)
	for rows.Next() {
		var device registry.Device
		var state string
		var replacedBy *string
		if err := rows.Scan(&device.ID, &device.UserID, &device.DeviceModel, &device.Transport, &state, &device.CreatedAt, &device.UpdatedAt, &device.RevokedAt, &replacedBy); err != nil {
			return nil, fmt.Errorf("scan registered device: %w", err)
		}
		device.State = registry.LifecycleState(state)
		if replacedBy != nil {
			device.ReplacedByID = *replacedBy
		}
		result = append(result, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate registered devices: %w", err)
	}
	return result, nil
}

func (r *DeviceRegistry) AuthorizeAttestation(ctx context.Context, userID, deviceID, provider, keyID string) error {
	device, err := r.getOwnedDevice(ctx, userID, deviceID)
	if err != nil {
		return err
	}
	if !registry.IsUsable(device.State) {
		return registry.ErrDeviceUnavailable
	}
	var boundDevice string
	var state string
	err = r.pool.QueryRow(ctx, `SELECT device_id, lifecycle_state FROM registered_device_attestations WHERE provider = $1 AND key_id = $2`, provider, keyID).Scan(&boundDevice, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("authorize device attestation: %w", err)
	}
	if boundDevice != deviceID {
		return registry.ErrKeyBoundElsewhere
	}
	switch registry.LifecycleState(state) {
	case registry.StateRevoked:
		return registry.ErrKeyRevoked
	case registry.StateReplaced:
		return registry.ErrKeyReplaced
	}
	return nil
}

func (r *DeviceRegistry) RegisterAttestation(ctx context.Context, userID, deviceID string, metadata registry.KeyMetadata, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device attestation registration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owner string
	var state string
	if err := tx.QueryRow(ctx, `SELECT user_id, lifecycle_state FROM registered_devices WHERE id = $1 FOR UPDATE`, deviceID).Scan(&owner, &state); errors.Is(err, pgx.ErrNoRows) {
		return registry.ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("lock registered device: %w", err)
	}
	if owner != userID {
		return registry.ErrDeviceNotOwned
	}
	if !registry.IsUsable(registry.LifecycleState(state)) {
		return registry.ErrDeviceUnavailable
	}
	var existingDevice, existingState string
	var existingCounter int64
	err = tx.QueryRow(ctx, `SELECT device_id, lifecycle_state, counter FROM registered_device_attestations WHERE provider = $1 AND key_id = $2 FOR UPDATE`, metadata.Provider, metadata.KeyID).Scan(&existingDevice, &existingState, &existingCounter)
	if err == nil {
		if existingDevice != deviceID {
			return registry.ErrKeyBoundElsewhere
		}
		if existingState == string(registry.StateRevoked) || existingState == string(registry.StateReplaced) {
			return registry.ErrKeyRevoked
		}
		if metadata.Counter <= uint64(existingCounter) {
			return registry.ErrCounterRollback
		}
		_, err = tx.Exec(ctx, `UPDATE registered_device_attestations SET public_key_der = $1, bundle_version = NULLIF($2, ''), environment = NULLIF($3, ''), counter = $4, last_seen_at = $5 WHERE provider = $6 AND key_id = $7`, metadata.PublicKeyDER, metadata.BundleVersion, metadata.Environment, metadata.Counter, now, metadata.Provider, metadata.KeyID)
		if err != nil {
			return fmt.Errorf("update registered attestation: %w", err)
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `UPDATE registered_device_attestations SET lifecycle_state = $1, replaced_by_key = $2 WHERE device_id = $3 AND provider = $4 AND lifecycle_state = $5`, registry.StateReplaced, metadata.KeyID, deviceID, metadata.Provider, registry.StateActive)
		if err != nil {
			return fmt.Errorf("rotate registered attestation: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO registered_device_attestations (device_id, provider, key_id, public_key_der, bundle_version, environment, counter, lifecycle_state, registered_at, last_seen_at) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $9)`, deviceID, metadata.Provider, metadata.KeyID, metadata.PublicKeyDER, metadata.BundleVersion, metadata.Environment, metadata.Counter, registry.StateActive, now)
		if err != nil {
			return fmt.Errorf("insert registered attestation: %w", err)
		}
	} else {
		return fmt.Errorf("find registered attestation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE registered_devices SET lifecycle_state = $1, updated_at = $2 WHERE id = $3`, registry.StateActive, now, deviceID); err != nil {
		return fmt.Errorf("activate registered device: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit registered attestation: %w", err)
	}
	return nil
}

func (r *DeviceRegistry) RevokeDevice(ctx context.Context, userID, deviceID, reason string, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owner string
	if err := tx.QueryRow(ctx, `SELECT user_id FROM registered_devices WHERE id = $1 FOR UPDATE`, deviceID).Scan(&owner); errors.Is(err, pgx.ErrNoRows) {
		return registry.ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("lock device for revocation: %w", err)
	}
	if owner != userID {
		return registry.ErrDeviceNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE registered_devices SET lifecycle_state = $1, revoked_at = $2, updated_at = $2 WHERE id = $3 AND lifecycle_state <> $4`, registry.StateRevoked, now, deviceID, registry.StateRetired); err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE registered_device_attestations SET lifecycle_state = $1, revoked_at = $2 WHERE device_id = $3 AND lifecycle_state = $4`, registry.StateRevoked, now, deviceID, registry.StateActive); err != nil {
		return fmt.Errorf("revoke device keys: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO device_key_revocations (provider, key_id, reason_code, revoked_at) SELECT provider, key_id, $1, $2 FROM registered_device_attestations WHERE device_id = $3 ON CONFLICT (provider, key_id) DO UPDATE SET reason_code = EXCLUDED.reason_code, revoked_at = EXCLUDED.revoked_at`, reason, now, deviceID); err != nil {
		return fmt.Errorf("record key revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit device revocation: %w", err)
	}
	return nil
}

func (r *DeviceRegistry) SetLifecycle(ctx context.Context, userID, deviceID string, next registry.LifecycleState, reason string, now time.Time) error {
	if next != registry.StateActive && next != registry.StateSuspended && next != registry.StateRetired {
		return registry.ErrInvalidLifecycle
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device lifecycle change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owner, current string
	if err := tx.QueryRow(ctx, `SELECT user_id, lifecycle_state FROM registered_devices WHERE id = $1 FOR UPDATE`, deviceID).Scan(&owner, &current); errors.Is(err, pgx.ErrNoRows) {
		return registry.ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("lock device lifecycle: %w", err)
	}
	if owner != userID {
		return registry.ErrDeviceNotFound
	}
	valid := (current == string(registry.StateActive) && (next == registry.StateSuspended || next == registry.StateRetired)) || (current == string(registry.StateSuspended) && next == registry.StateActive)
	if !valid {
		return registry.ErrInvalidLifecycle
	}
	if _, err := tx.Exec(ctx, `UPDATE registered_devices SET lifecycle_state = $1, updated_at = $2 WHERE id = $3`, next, now, deviceID); err != nil {
		return fmt.Errorf("set device lifecycle: %w", err)
	}
	if next == registry.StateRetired {
		if _, err := tx.Exec(ctx, `UPDATE registered_device_attestations SET lifecycle_state = $1, revoked_at = $2 WHERE device_id = $3 AND lifecycle_state = $4`, registry.StateRevoked, now, deviceID, registry.StateActive); err != nil {
			return fmt.Errorf("retire device keys: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit device lifecycle: %w", err)
	}
	_ = reason
	return nil
}

func (r *DeviceRegistry) ReplaceDevice(ctx context.Context, userID, deviceID, newUID, model, transport string, now time.Time) (registry.Device, error) {
	old, err := r.getOwnedDevice(ctx, userID, deviceID)
	if err != nil {
		return registry.Device{}, err
	}
	if !registry.IsUsable(old.State) {
		return registry.Device{}, registry.ErrDeviceUnavailable
	}
	newDevice, err := r.EnsureDevice(ctx, userID, newUID, model, transport, now)
	if err != nil {
		return registry.Device{}, err
	}
	if newDevice.ID == deviceID {
		return registry.Device{}, registry.ErrReplacementRequired
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return registry.Device{}, fmt.Errorf("begin device replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE registered_devices SET lifecycle_state = $1, replaced_by_id = $2, updated_at = $3 WHERE id = $4 AND user_id = $5`, registry.StateReplaced, newDevice.ID, now, deviceID, userID); err != nil {
		return registry.Device{}, fmt.Errorf("replace device: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE registered_device_attestations SET lifecycle_state = $1 WHERE device_id = $2 AND lifecycle_state = $3`, registry.StateReplaced, deviceID, registry.StateActive); err != nil {
		return registry.Device{}, fmt.Errorf("replace device keys: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return registry.Device{}, fmt.Errorf("commit device replacement: %w", err)
	}
	return newDevice, nil
}

func (r *DeviceRegistry) getOwnedDevice(ctx context.Context, userID, deviceID string) (registry.Device, error) {
	var device registry.Device
	var state string
	var replacedBy *string
	err := r.pool.QueryRow(ctx, `SELECT id, user_id, device_model, transport, lifecycle_state, created_at, updated_at, revoked_at, replaced_by_id FROM registered_devices WHERE id = $1 AND user_id = $2`, deviceID, userID).Scan(&device.ID, &device.UserID, &device.DeviceModel, &device.Transport, &state, &device.CreatedAt, &device.UpdatedAt, &device.RevokedAt, &replacedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Device{}, registry.ErrDeviceNotFound
	}
	if err != nil {
		return registry.Device{}, fmt.Errorf("get registered device: %w", err)
	}
	device.State = registry.LifecycleState(state)
	if replacedBy != nil {
		device.ReplacedByID = *replacedBy
	}
	return device, nil
}

func newDeviceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate device id: %w", err)
	}
	return "dev_" + hex.EncodeToString(buf), nil
}
