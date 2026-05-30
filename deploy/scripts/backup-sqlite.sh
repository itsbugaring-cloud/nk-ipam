#!/usr/bin/env sh
set -eu

DB_PATH="${1:-/opt/netking-ipam/data/netking.db}"
BACKUP_DIR="${2:-/opt/netking-ipam/data/backups}"

mkdir -p "$BACKUP_DIR"

STAMP="$(date +%F-%H%M%S)"
sqlite3 "$DB_PATH" ".backup ${BACKUP_DIR}/netking-${STAMP}.db"

echo "Backup created at ${BACKUP_DIR}/netking-${STAMP}.db"
