#!/usr/bin/env bash
#
# feature-overview-snapshot.sh
#
# Creates a new Feature-Overview-<timestamp>.md snapshot in the repo
# root, seeded from the most recent existing snapshot. The older
# files are kept untouched so the project keeps a historical trail
# of feature states over time.
#
# Workflow:
#   1. Run this script — it creates Feature-Overview-<now>.md as a
#      copy of the latest snapshot, with the Timestamp line updated.
#   2. Edit the new file to record what has changed since the
#      previous snapshot.
#   3. Diff against the previous file (sorted-by-name = sorted by
#      timestamp) to see the per-snapshot delta:
#        diff Feature-Overview-<previous>.md Feature-Overview-<new>.md
#
# Usage:
#   ./scripts/feature-overview-snapshot.sh
#   ./scripts/feature-overview-snapshot.sh "state after V00.71 release"
#
# An optional first argument is appended to the Timestamp line as
# context (e.g. "state after V00.71 release", "mid-cycle"). If
# omitted and the previous snapshot's Timestamp line had context,
# that context is preserved verbatim.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
TIMESTAMP=$(date "+%Y-%m-%d_%H-%M-%S")
TIMEZONE="Europe/Berlin"
CONTEXT="${1:-}"

NEW_FILE="$REPO_ROOT/Feature-Overview-$TIMESTAMP.md"

# Find the latest existing snapshot. Filenames are
# Feature-Overview-<YYYY-MM-DD>_<HH-MM-SS>.md — `sort` orders them
# chronologically. `mapfile` isn't available in macOS' bash 3.x, so
# use a plain `ls` pipeline.
LATEST=$(ls -1 "$REPO_ROOT"/Feature-Overview-*.md 2>/dev/null | sort | tail -1)

if [ -z "$LATEST" ]; then
    echo "ERROR: no existing Feature-Overview-*.md found in $REPO_ROOT." >&2
    echo "       Create one manually first; this script needs a seed file." >&2
    exit 1
fi

if [ "$LATEST" = "$NEW_FILE" ]; then
    echo "ERROR: latest snapshot already has the current timestamp." >&2
    echo "       Wait at least one second and re-run." >&2
    exit 1
fi

cp "$LATEST" "$NEW_FILE"

# Build the new Timestamp line. Two cases:
#   - $CONTEXT given          → "Timestamp: <ts> <tz> ($CONTEXT)"
#   - $CONTEXT empty          → preserve the previous snapshot's
#                              optional "(…)" suffix verbatim
if [ -n "$CONTEXT" ]; then
    NEW_TIMESTAMP_LINE="Timestamp: $TIMESTAMP $TIMEZONE ($CONTEXT)"
else
    PREV_SUFFIX=$(grep -m 1 -E "^Timestamp: " "$LATEST" \
        | sed -E 's/^Timestamp: [0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2} [^ ]+ ?//' \
        | sed -E 's/^[[:space:]]*//')
    if [ -n "$PREV_SUFFIX" ]; then
        NEW_TIMESTAMP_LINE="Timestamp: $TIMESTAMP $TIMEZONE $PREV_SUFFIX"
    else
        NEW_TIMESTAMP_LINE="Timestamp: $TIMESTAMP $TIMEZONE"
    fi
fi

# Replace the first Timestamp: line. macOS sed needs an empty arg
# after -i; GNU sed does not.
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "1,/^Timestamp: /s|^Timestamp: .*|${NEW_TIMESTAMP_LINE}|" "$NEW_FILE"
else
    sed -i "1,/^Timestamp: /s|^Timestamp: .*|${NEW_TIMESTAMP_LINE}|" "$NEW_FILE"
fi

echo "Created: $(basename "$NEW_FILE")"
echo "Seed:    $(basename "$LATEST")"
echo "Tline:   $NEW_TIMESTAMP_LINE"
echo ""
echo "Edit the new file to record what changed since $(basename "$LATEST")."
echo "Diff:    diff '$LATEST' '$NEW_FILE'"
