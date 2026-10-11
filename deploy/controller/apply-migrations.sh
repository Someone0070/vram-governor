#!/usr/bin/env bash
set -euo pipefail

migration_dir=${MIGRATION_DIR:-/usr/local/share/vram-governor/migrations}
database_url=${VRAM_MIGRATION_DATABASE_URL:-postgresql:///vram_governor?host=/var/run/postgresql}
only_migration=""
if [[ ${1:-} == "--only" && $# -eq 2 ]]; then
  only_migration=$2
  [[ "$only_migration" =~ ^[0-9]{4}_[A-Za-z0-9_-]+\.sql$ ]] || { echo "invalid migration filename" >&2; exit 2; }
elif [[ $# -ne 0 ]]; then
  echo "usage: apply-migrations.sh [--only 0017_name.sql]" >&2
  exit 2
fi

command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }
[[ -d "$migration_dir" ]] || { echo "migration directory not found: $migration_dir" >&2; exit 1; }

shopt -s nullglob
migrations=("$migration_dir"/[0-9][0-9][0-9][0-9]_*.sql)
[[ ${#migrations[@]} -gt 0 ]] || { echo "no ordered migrations found" >&2; exit 1; }
if [[ -n "$only_migration" && ! -f "$migration_dir/$only_migration" ]]; then
  echo "migration not found: $only_migration" >&2
  exit 1
fi

for migration in "${migrations[@]}"; do
  if [[ -n "$only_migration" && $(basename "$migration") != "$only_migration" ]]; then continue; fi
  echo "applying $(basename "$migration")"
  psql "$database_url" -v ON_ERROR_STOP=1 -f "$migration"
done
