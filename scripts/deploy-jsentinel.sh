#!/usr/bin/env bash
# Deploy the community libraries to repo.jsentinel.eu/{releases,snapshots}.
# Maven Central is published through the bundle script instead, not from here.
#
# Demo modules are excluded, and the goal is named explicitly because the plain
# deploy phase uploads nothing under this parent (see the enterprise script).
set -euo pipefail
cd "$(dirname "$0")/.."
LOG="${TMPDIR:-/tmp}/jcustos-community-deploy.log"
LIBS=$(grep '<module>' pom.xml | sed -E 's/.*<module>(.*)<\/module>.*/\1/' | grep -v '^demo' | paste -sd, -)
./mvnw -N package deploy:deploy "$@" > "$LOG" 2>&1
./mvnw package deploy:deploy -pl "$LIBS" "$@" >> "$LOG" 2>&1
echo "deployed $(echo "$LIBS" | tr ',' '\n' | wc -l | tr -d ' ') modules + parent — log: $LOG"
