#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec cargo run --quiet --bin kurrentctl -- run-ln-to-kaspa-flow
