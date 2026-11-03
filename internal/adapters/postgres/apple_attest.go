package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/attestation"
)

type AppleAppAttestKeyStore struct{ pool *pgxpool.Pool }

func NewAppleAppAttestKeyStore(pool *pgxpool.Pool) *AppleAppAttestKeyStore {
	return &AppleAppAttestKeyStore{pool: pool}
}

func (s *AppleAppAttestKeyStore) Get(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	var der []byte
	if err := s.pool.QueryRow(ctx, `SELECT public_key FROM apple_app_attest_keys WHERE key_id = $1 LIMIT 1`, keyID).Scan(&der); err != nil {
		if err == pgx.ErrNoRows {
			return nil, attestation.ErrAppleInvalidKeyID
		}
		return nil, fmt.Errorf("get apple app attest key: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse apple app attest key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, attestation.ErrAppleInvalidKeyID
	}
	return ecdsaKey, nil
}

func (s *AppleAppAttestKeyStore) Put(ctx context.Context, keyID string, key *ecdsa.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshal apple app attest key: %w", err)
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO apple_app_attest_keys (key_id, public_key, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key_id) DO UPDATE SET public_key = EXCLUDED.public_key, updated_at = now()`, keyID, der)
	if err != nil {
		return fmt.Errorf("save apple app attest key: %w", err)
	}
	return nil
}
