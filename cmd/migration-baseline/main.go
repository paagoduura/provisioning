package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "migration checksum baseline failed:", err)
		os.Exit(1)
	}
}

func run() error {
	accept := flag.Bool("accept-current-migration-files-as-baseline", false, "confirm that current migration files have been reviewed against the legacy database schema")
	flag.Parse()
	if !*accept {
		return errors.New("refusing implicit checksum baseline; pass --accept-current-migration-files-as-baseline only after reviewing the deployed migration history")
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
	if err := migrations.BaselineLegacyChecksums(ctx, pool); err != nil {
		return err
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		return fmt.Errorf("apply and verify migrations: %w", err)
	}
	fmt.Println("Legacy checksums baselined; migration history verified and current migrations applied.")
	return nil
}
