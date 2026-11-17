#!/usr/bin/env bash
set -Eeuo pipefail

# Perform a logical-dump restore rehearsal against a disposable local database.
# This script never drops or overwrites the source database and never targets a
# caller-selected restore database. It deliberately supports local socket
# connections only; production credentials/storage/encryption are operator work.

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/postgres-backup-rehearsal.sh --service SERVICE --source-db DATABASE [--output-dir DIRECTORY]

Connects through libpq's named service in PGSERVICEFILE (or ~/.pg_service.conf),
creates a custom-format pg_dump archive and SHA-256 manifest, then restores it
into an internally generated disposable database on the local Unix socket.
Requires PostgreSQL 16 client tools (pg_dump, pg_restore, psql, createdb, dropdb).
The output directory must not already exist. PGSERVICEFILE should use a local
Unix socket and a trusted local role; this rehearsal intentionally rejects TCP.
USAGE
}

fail() { echo "backup rehearsal: $*" >&2; exit 2; }

service="${PGSERVICE:-}"
source_db="${SOURCE_DB:-}"
output_dir="${OUTPUT_DIR:-}"
while (($#)); do
  case "$1" in
    --service) (($# >= 2)) || fail "--service requires a value"; service="$2"; shift 2 ;;
    --source-db) (($# >= 2)) || fail "--source-db requires a value"; source_db="$2"; shift 2 ;;
    --output-dir) (($# >= 2)) || fail "--output-dir requires a value"; output_dir="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$service" ]] || fail "set PGSERVICE to a local Unix-socket service name"
[[ -n "$source_db" ]] || fail "set SOURCE_DB to a disposable PostgreSQL 16 database name"
[[ "$service" =~ ^[A-Za-z0-9_.-]{1,63}$ ]] || fail "provide a valid named PostgreSQL service"
[[ "$source_db" =~ ^[A-Za-z0-9_.-]{1,63}$ ]] || fail "provide a simple database name (letters, digits, underscore, dot, hyphen)"
[[ -n "${PGSERVICEFILE:-}" && -r "$PGSERVICEFILE" ]] || fail "set PGSERVICEFILE to a readable libpq service file; no credentials are accepted on the command line"
command -v pg_dump >/dev/null || fail "pg_dump not installed"
command -v pg_restore >/dev/null || fail "pg_restore not installed"
command -v psql >/dev/null || fail "psql not installed"
command -v createdb >/dev/null || fail "createdb not installed"
command -v dropdb >/dev/null || fail "dropdb not installed"
command -v sha256sum >/dev/null || fail "sha256sum not installed"

# Pin the rehearsal client to PostgreSQL 16 to match the supported project DB.
for tool in pg_dump pg_restore; do
  version="$($tool --version)"
  [[ "$version" =~ \ 16\.[0-9]+ ]] || fail "$tool must be PostgreSQL 16.x; found: $version"
done

# Read the selected service config and accept only local Unix-domain sockets.
# Reject service expansion/inheritance and environment overrides that could
# redirect individual libpq clients to a remote database.
if env | grep -Eq '^PG(HOST|HOSTADDR|PORT|DATABASE|USER|PASSWORD|PASSFILE|OPTIONS|TARGET_SESSION_ATTRS)='; then
  fail "unset PGHOST/PGHOSTADDR/PGPORT/PGDATABASE/PGUSER/PGPASSWORD/PGPASSFILE/PGOPTIONS/PGTARGETSESSIONATTRS overrides"
fi
service_block="$(awk -v target="$service" '
  /^\[[^]]+\][[:space:]]*$/ { current=$0; sub(/^\[/,"",current); sub(/\][[:space:]]*$/,"",current); next }
	  current==target && $0 !~ /^[[:space:]]*[#;]/ && /=/ { print }
' "$PGSERVICEFILE")"
[[ -n "$service_block" ]] || fail "service '$service' not found in PGSERVICEFILE"
if grep -Eiq '^[[:space:]]*(hostaddr|port|host|service|servicefile|dbname|user|password|passfile|options|target_session_attrs)[[:space:]]*=' <<<"$service_block"; then
  # host is allowed only when it is an absolute Unix socket directory.
  host_count="$(grep -Eic '^[[:space:]]*host[[:space:]]*=' <<<"$service_block")"
  [[ "$host_count" == "1" ]] || fail "service must contain exactly one host setting"
  host_value="$(awk -F= 'tolower($1) ~ /^[[:space:]]*host[[:space:]]*$/ {sub(/^[^=]*=/,""); print; exit}' <<<"$service_block" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ "$host_value" == /* ]] || fail "service must specify host as a local Unix socket directory"
  if grep -Eiv '^[[:space:]]*host[[:space:]]*=' <<<"$service_block" | grep -q .; then
    fail "service may contain only a local Unix socket host; do not put credentials or other connection settings in it"
  fi
else
  fail "service must explicitly specify a local Unix socket host"
fi

if [[ -z "$output_dir" ]]; then
  output_dir="$(pwd)/backups/rehearsal-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
[[ ! -e "$output_dir" ]] || fail "output directory already exists: $output_dir"
umask 077
mkdir -p -- "$(dirname -- "$output_dir")"
mkdir -m 0700 -- "$output_dir"
archive="$output_dir/${source_db}.dump"
manifest="$output_dir/manifest.txt"
restore_db="provisioning_restore_rehearsal_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$restore_db" =~ ^[a-z0-9_]+$ ]] || fail "internal restore database name invalid"
created=0
cleanup() {
  status=$?
  if ((created)); then
    if ! dropdb --if-exists --maintenance-db="service=$service dbname=postgres" "$restore_db"; then
      echo "backup rehearsal: WARNING: could not drop disposable restore database $restore_db; remove it manually after verifying no other process uses it" >&2
      status=1
    fi
  fi
  if ((status != 0)); then
    echo "backup rehearsal: failed; output directory retained for investigation: $output_dir" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

server_version="$(psql --no-psqlrc --tuples-only --no-align --dbname="service=$service dbname=$source_db" --command='SHOW server_version_num')"
[[ "$server_version" =~ ^160[0-9]{3}$ ]] || fail "source server must be PostgreSQL 16.x; got server_version_num=$server_version"

# pg_dump uses a single consistent database snapshot. --no-password avoids a
# prompt that could stall unattended operations; authentication must come from
# the named local service/trusted local peer authentication.
pg_dump --no-password --verbose --format=custom --compress=6 --dbname="service=$service dbname=$source_db" --file="$archive"
chmod 0600 "$archive"
pg_restore --list "$archive" > "$output_dir/archive.toc"
chmod 0600 "$output_dir/archive.toc"
archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
{
  printf 'format=postgresql-custom\n'
  printf 'database=%s\n' "$source_db"
  printf 'source_server_version_num=%s\n' "$server_version"
  printf 'pg_dump_version=%s\n' "$(pg_dump --version)"
  printf 'created_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'archive_file=%s\n' "$(basename "$archive")"
  printf 'archive_sha256=%s\n' "$archive_sha"
  printf 'scope=single_database_logical_dump; roles_and_tablespaces_not_included\n'
  printf 'rehearsal_target=local_disposable_database; not_production_pitr_evidence\n'
} > "$manifest"
chmod 0600 "$manifest"

verified_sha="$(sha256sum "$archive" | awk '{print $1}')"
[[ "$verified_sha" == "$archive_sha" ]] || fail "archive SHA-256 verification failed before restore"

# Ensure the internally generated target is absent before create; restore only
# into this new empty database, never with --clean/--create or an operator name.
exists="$(psql --no-psqlrc --tuples-only --no-align --dbname="service=$service dbname=postgres" --command="SELECT count(*) FROM pg_database WHERE datname = '$restore_db'")"
[[ "$exists" == "0" ]] || fail "generated disposable database unexpectedly already exists"
createdb --no-password --maintenance-db="service=$service dbname=postgres" --template=template0 "$restore_db"
created=1
pg_restore --no-password --exit-on-error --single-transaction --dbname="service=$service dbname=$restore_db" "$archive"
psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="service=$service dbname=$restore_db" --command='ANALYZE'

# Verify restored ledger rows and checksum lengths without assuming a production
# baseline; deployments with an older no-checksum schema are surfaced as output.
if psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname="service=$service dbname=$restore_db" --command="SELECT to_regclass('public.schema_migrations') IS NOT NULL" | grep -qx t; then
  ledger_total=$(psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname="service=$service dbname=$restore_db" --command 'SELECT count(*) FROM public.schema_migrations')
  invalid=$(psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname="service=$service dbname=$restore_db" --command 'SELECT count(*) FROM public.schema_migrations WHERE checksum IS NULL OR octet_length(checksum) <> 32')
  ledger_summary="$ledger_total:$invalid"
  printf 'restored_migration_ledger_total_and_invalid_checksums=%s\n' "$ledger_summary" >> "$manifest"
  [[ "$invalid" == "0" ]] || fail "restored database has missing or malformed migration checksums ($ledger_summary); investigate source state"
else
  fail "restored database has no public.schema_migrations table; investigate source state"
fi

restored_server_version="$(psql --no-psqlrc --tuples-only --no-align --dbname="service=$service dbname=$restore_db" --command="SHOW server_version_num")"
[[ "$restored_server_version" == "$server_version" ]] || fail "restored target server version differs from source"

echo "Backup archive and metadata: $output_dir"
echo "Restore rehearsal succeeded against disposable local database $restore_db"
