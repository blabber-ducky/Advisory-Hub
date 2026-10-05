#!/usr/bin/env bash
# Convert the manual tracker workbook (.xlsx, all month sheets) into the CSV
# the tool's "Import manual tracker" page accepts.
#
#   scripts/tracker-to-csv.sh Security_Advisories-2026.xlsx
#   scripts/tracker-to-csv.sh Security_Advisories-2026.xlsx out/tracker.csv
#
# The conversion itself is the app's own (`advisory-hub tracker-to-csv`, the
# same code as the import page's "Download as CSV"), so the CSV is exactly
# what the tool would compute. This script just finds a way to run it:
#
#   1. In a checkout with the project's .venv — runs it directly.
#   2. Otherwise with Docker — runs the published image with no network, a
#      read-only filesystem, as you (not root), the workbook mounted
#      read-only. Image: $IMAGE, else <IMAGE_NAMESPACE>/advisory-hub:<IMAGE_TAG>
#      from ./.env, else IMAGE_NAMESPACE/IMAGE_TAG from the environment.
#
# Set TRACKER_TO_CSV_USE_DOCKER=1 to force Docker even when a .venv exists.
# Output columns and the status rules: docs/architecture.md §3.3.3.

set -euo pipefail

die()   { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; }

[[ $# -ge 1 && $# -le 2 ]] || { usage; exit 1; }
[[ "$1" == "-h" || "$1" == "--help" ]] && { usage; exit 0; }

input="$1"
[[ -f "$input" ]] || die "$input not found"
[[ "$input" == *.xlsx || "$input" == *.XLSX ]] || die "$input is not an .xlsx workbook"

output="${2:-${input%.*}.csv}"
out_dir="$(dirname "$output")"
[[ -d "$out_dir" ]] || die "output folder $out_dir doesn't exist"
[[ -e "$output" ]] && printf 'note: overwriting %s\n' "$output" >&2

# Absolute paths — the Docker route mounts their folders.
abs() { (cd "$(dirname "$1")" && printf '%s/%s' "$(pwd)" "$(basename "$1")"); }
input_abs="$(abs "$input")"
output_abs="$(abs "$output")"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$ROOT/.venv/bin/python"

if [[ -x "$VENV_PY" && "${TRACKER_TO_CSV_USE_DOCKER:-0}" != 1 ]]; then
  cd "$ROOT"
  exec "$VENV_PY" -m advisory_hub.cli tracker-to-csv "$input_abs" -o "$output_abs"
fi

command -v docker >/dev/null || die "needs either the project's .venv or Docker"

if [[ -z "${IMAGE:-}" ]]; then
  env_get() { [[ -f "$ROOT/.env" ]] && sed -n "s/^$1=//p" "$ROOT/.env" | tail -1; true; }
  ns="${IMAGE_NAMESPACE:-$(env_get IMAGE_NAMESPACE)}"
  tag="${IMAGE_TAG:-$(env_get IMAGE_TAG)}"
  [[ -n "$ns" ]] || die "set IMAGE (e.g. IMAGE=acme/advisory-hub:latest) or IMAGE_NAMESPACE"
  IMAGE="$ns/advisory-hub:${tag:-latest}"
fi

# The workbook is untrusted input from outside the org: no network, nothing
# writable but the output folder, not root. The output file is written
# straight into its folder under its final name by the converter.
docker run --rm \
  --network none \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$(dirname "$input_abs")":/in:ro \
  -v "$(dirname "$output_abs")":/out \
  "$IMAGE" \
  python -m advisory_hub.cli tracker-to-csv "/in/$(basename "$input_abs")" -o "/out/$(basename "$output_abs")"
# The converter reports the in-container path (/out/...); say where it really is.
printf 'Saved to %s\n' "$output_abs"
