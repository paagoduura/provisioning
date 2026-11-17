package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/adapters/postgres"
	"github.com/paagoduura/provisioning/internal/retention"
	"github.com/paagoduura/provisioning/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "retention purge failed:", err)
		os.Exit(1)
	}
}

func run() error {
	policy, err := policyFromEnv()
	if err != nil {
		return err
	}
	batchSize, err := strconv.Atoi(os.Getenv("RETENTION_PURGE_BATCH_SIZE"))
	if err != nil {
		return errors.New("RETENTION_PURGE_BATCH_SIZE must be set to an integer between 1 and 1000")
	}
	limits := retention.Limits{BatchSize: batchSize}
	if err := limits.Validate(); err != nil {
		return err
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping PostgreSQL: %w", err)
	}
	if err := migrations.Verify(ctx, pool); err != nil {
		return fmt.Errorf("verify migration ledger before purge: %w", err)
	}
	counts, err := postgres.NewSessionRepository(pool).PurgeExpired(ctx, time.Now().UTC(), policy, limits)
	if err != nil {
		return err
	}
	fmt.Printf("retention purge complete: audit_events=%d challenges=%d webhook_events=%d sessions=%d device_attestations=%d token_operations=%d batch_size=%d\n", counts.AuditEvents, counts.Challenges, counts.WebhookEvents, counts.Sessions, counts.DeviceAttestations, counts.TokenOperations, limits.BatchSize)
	return nil
}

func policyFromEnv() (retention.Policy, error) {
	read := func(name string) (time.Duration, error) {
		value := os.Getenv(name)
		if value == "" {
			return 0, fmt.Errorf("%s must be explicitly set to the approved retention duration", name)
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return 0, fmt.Errorf("%s must be a positive Go duration", name)
		}
		return duration, nil
	}
	challenge, err := read("RETENTION_EXPIRED_CHALLENGE_AGE")
	if err != nil {
		return retention.Policy{}, err
	}
	session, err := read("RETENTION_EXPIRED_SESSION_AGE")
	if err != nil {
		return retention.Policy{}, err
	}
	webhook, err := read("RETENTION_WEBHOOK_EVENT_AGE")
	if err != nil {
		return retention.Policy{}, err
	}
	audit, err := read("RETENTION_AUDIT_EVENT_AGE")
	if err != nil {
		return retention.Policy{}, err
	}
	policy := retention.Policy{ExpiredChallengeAge: challenge, ExpiredSessionAge: session, WebhookEventAge: webhook, AuditEventAge: audit}
	if err := policy.Validate(); err != nil {
		return retention.Policy{}, err
	}
	return policy, nil
}
