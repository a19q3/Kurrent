#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${KURRENT_ACCEPTANCE_LOGGING:-1}" != "0" ]]; then
  LOG_DIR="${KURRENT_ACCEPTANCE_LOG_DIR:-$ROOT/evidence/acceptance-logs}"
  mkdir -p "$LOG_DIR"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  LOG_PATH="${KURRENT_ACCEPTANCE_LOG_PATH:-$LOG_DIR/local-devnet-acceptance-$timestamp.log}"
  mkdir -p "$(dirname "$LOG_PATH")"

  {
    echo "Kurrent local devnet acceptance full log"
    echo "started_utc=$timestamp"
    echo "cwd=$ROOT"
    echo "git_commit=$(git rev-parse --verify HEAD 2>/dev/null || true)"
    echo "command=cargo run --quiet --bin kurrentctl -- check"
    echo "----- begin acceptance output -----"
  } > "$LOG_PATH"

  set +e
  KURRENT_ACCEPTANCE_LOGGING=0 "$0" "$@" 2>&1 | tee -a "$LOG_PATH"
  status="${PIPESTATUS[0]}"
  set -e

  {
    echo "----- end acceptance output -----"
    echo "finished_utc=$(date -u +%Y%m%dT%H%M%SZ)"
    echo "exit_code=$status"
    echo "full_log=$LOG_PATH"
    echo "latest_log=$LOG_DIR/latest.log"
  } | tee -a "$LOG_PATH"

  latest_path="$LOG_DIR/latest.log"
  log_abs="$(cd "$(dirname "$LOG_PATH")" && pwd)/$(basename "$LOG_PATH")"
  latest_abs="$(cd "$(dirname "$latest_path")" && pwd)/$(basename "$latest_path")"
  if [[ "$log_abs" != "$latest_abs" ]]; then
    cp "$LOG_PATH" "$latest_path"
  fi
  exit "$status"
fi

exec cargo run --quiet --bin kurrentctl -- check
