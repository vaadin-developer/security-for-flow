#!/usr/bin/env bash
#
# Builds a Central Portal-compatible bundle from artifacts in the local Maven
# repository.
#
# Background: central-publishing-maven-plugin 0.10.0 under Maven 4.0.0-rc-5 is
# broken — it logs "Installing X.jar to central-staging/" for every module, but
# the resulting central-bundle.zip ends up with only the POMs (no jar, no
# sources, no javadoc, no .asc, no checksums). Central then rejects the upload
# with hundreds of "Failed to associate file with coordinates" errors. The
# plugin warning at the end of the reactor build is explicit:
#
#   * org.sonatype.central:central-publishing-maven-plugin:0.10.0
#     - Plugin depends on the deprecated Maven 2.x compatibility layer …
#     - Plugin mixes multiple Maven versions: [3.9.0, 3.9.2]
#
# This script bypasses the plugin and assembles the bundle directly from
# ~/.m2/repository, where Maven 4's installer already names the consumer POM
# correctly (<artifact>-<version>.pom) and keeps the build POM as a separate
# -build classifier we drop here.
#
# Prerequisite:
#   ./mvnw clean install -P _release_sign-artifacts,_java,_release_prepare,gpg
#
# That populates ~/.m2/repository/com/svenruppert/<module>/<version>/ with the
# signed jar / sources / javadoc / pom (plus their .asc signatures).
#
# Usage:
#   ./scripts/clean-bundle-for-central.sh             # version from pom.xml
#   ./scripts/clean-bundle-for-central.sh 00.74.00    # explicit version

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
M2_REPO="${HOME}/.m2/repository"
# Coordinates history: V00.73 moved the groupId com.svenruppert ->
# com.svenruppert.jsentinel; the V00.81.10 jCustos rebrand moved it to
# eu.jsentinel (external com.svenruppert:* deps keep their groupId —
# those are not produced here).
GROUP_PATH="eu/jsentinel"

# Library modules that should appear on Maven Central. The demo modules
# (demo-vaadin, demo-rest, demo-vaadin-rest-client, demo-standalone,
# demo-rest-shared, demo-jsentinel-vaadin) are deliberately excluded —
# they are reference implementations, not publishable artefacts.
#
# Module list per release line:
#   V00.70 baseline (9): parent, core, test, vaadin, rest, standalone,
#                        processor, persistence-testkit, persistence-eclipsestore
#   V00.71 additions (2): crypto-bc, credentials-hibp
#   V00.72 additions (7): dx, dx-vaadin, dx-rest, dx-standalone,
#                         autoservice-annotations, autoservice-processor,
#                         vaadin-starter
#   V00.73 rename: artefacts took the jSentinel- prefix (parent was
#                  security-for-flow-parent before that);
#   V00.81.10 rename: all artefacts now use the jCustos- prefix.
#   V00.74 additions (3): propagation, propagation-processor,
#                         propagation-oidc — declarative token-forwarding
#                         surface (Konzept-V00.74).
#
# Note on jCustos-autoservice-processor: published even though
# consumers wire it via <annotationProcessorPath> rather than as a
# runtime dep. Central still needs the jar so the path can be resolved.
# Generated from the reactor's module list — keep it that way. A hand-maintained
# copy silently ships a stale set: this list still named nine modules that moved
# to the enterprise edition, and missed jCustos-bom entirely.
#   grep '<module>' pom.xml | sed -E 's/.*<module>(.*)<\/module>.*/\1/' | grep -v '^demo'
MODULES=(
    "jCustos-community-parent"
    "jCustos-bom"
    "jCustos-core"
    "jCustos-vaadin"
    "jCustos-rest"
    "jCustos-standalone"
    "jCustos-test"
    "jCustos-processor"
    "jCustos-persistence-testkit"
    "jCustos-persistence-eclipsestore"
    "jCustos-crypto-bc"
    "jCustos-credentials-hibp"
    "jCustos-autoservice-annotations"
    "jCustos-autoservice-processor"
    "jCustos-dx"
    "jCustos-dx-vaadin"
    "jCustos-dx-rest"
    "jCustos-dx-standalone"
    "jCustos-vaadin-starter"
    "jCustos-propagation"
    "jCustos-propagation-processor"
    "jCustos-propagation-oidc"
    "jCustos-events"
    "jCustos-events-testkit"
    "jCustos-jwt"
    "jCustos-oauth2"
    "jCustos-oauth2-vaadin"
    "jCustos-oauth2-rest"
    "jCustos-identity-oidc"
    "jCustos-identity-oidc-vaadin"
    "jCustos-identity-oidc-rest"
    "jCustos-test-oidc"
    "jCustos-identity-vendor-keycloak"
    "jCustos-identity-vendor-entra"
    "jCustos-identity-vendor-auth0"
    "jCustos-identity-vendor-okta"
    "jCustos-identity-vendor-google"
    "jCustos-identity-vendor-github"
    "jCustos-dpop"
)

if [ $# -ge 1 ]; then
    VERSION="$1"
else
    # Project <version> is the second <version> element in the parent pom.xml
    # (the first one is the <parent>'s version — com.svenruppert:dependencies).
    VERSION=$(grep -n -E '<version>[0-9]' "$REPO_ROOT/pom.xml" \
        | sed -n '2p' \
        | sed -E 's:.*<version>([^<]+)</version>.*:\1:')
fi

if [ -z "${VERSION:-}" ]; then
    echo "ERROR: could not read project <version> from pom.xml." >&2
    exit 1
fi

STAGING="$REPO_ROOT/target/central-bundle-staging"
BUNDLE_DIR="$REPO_ROOT/target/central-publishing"
BUNDLE="$BUNDLE_DIR/central-bundle.zip"

# Minimum acceptable size (bytes) for a -javadoc.jar. An empty javadoc jar
# (only META-INF/MANIFEST.MF, no rendered HTML) is ~300 B; the smallest real
# one we ship is ~111 KB (jCustos-autoservice-annotations). 50 KB sits
# safely between the two. This guard exists because 00.74.10 shipped EMPTY
# javadoc jars to Central: the maven-javadoc-plugin's addStylesheet pointed
# at the .gitignore'd build/javadoc/jsentinel.css, javadoc aborted, and
# failOnError=false swallowed the error. Fail the bundle here rather than
# discover it on Central (or worse, after publish — Central is immutable).
JAVADOC_MIN_BYTES=51200

rm -rf "$STAGING"
mkdir -p "$STAGING" "$BUNDLE_DIR"

generate_checksums() {
    local file="$1"
    if command -v md5sum >/dev/null 2>&1; then
        md5sum         "$file" | awk '{print $1}'   > "$file.md5"
    else
        md5 -q         "$file"                      > "$file.md5"
    fi
    shasum -a 1   "$file" | awk '{print $1}'   > "$file.sha1"
    shasum -a 256 "$file" | awk '{print $1}'   > "$file.sha256"
    shasum -a 512 "$file" | awk '{print $1}'   > "$file.sha512"
}

total_files=0
for module in "${MODULES[@]}"; do
    src="$M2_REPO/$GROUP_PATH/$module/$VERSION"
    dst="$STAGING/$GROUP_PATH/$module/$VERSION"

    if [ ! -d "$src" ]; then
        echo "ERROR: $src does not exist." >&2
        echo "       Run './mvnw clean install -P _release_sign-artifacts,_java,_release_prepare,gpg' first." >&2
        exit 1
    fi

    mkdir -p "$dst"

    # Keep: consumer pom (*.pom — Maven 4's local-repo name), main jar, sources,
    # javadoc, plus the .asc signature for each.
    # Drop: *-build.pom (Maven 4 build POM), tests + test-sources (Central
    #       doesn't accept these classifiers), _remote.repositories,
    #       *.lastUpdated.
    shopt -s nullglob
    for f in "$src"/*; do
        name=$(basename "$f")
        case "$name" in
            *-build.pom|*-build.pom.asc) continue ;;
            *-tests.jar|*-tests.jar.asc) continue ;;
            *-test-sources.jar|*-test-sources.jar.asc) continue ;;
            _remote.repositories|*.lastUpdated|*.repositories) continue ;;
            *.pom|*.pom.asc|*.jar|*.jar.asc)
                cp "$f" "$dst/"
                ;;
        esac
    done
    shopt -u nullglob

    # Guard: every non-parent module must carry a non-empty -javadoc.jar.
    # jCustos-parent is pom-packaging — it has no jar/javadoc at all.
    if [ "$module" != "jCustos-parent" ]; then
        jdoc="$dst/$module-$VERSION-javadoc.jar"
        if [ ! -f "$jdoc" ]; then
            echo "ERROR: $module $VERSION has no -javadoc.jar." >&2
            echo "       Expected: $jdoc" >&2
            exit 1
        fi
        jdoc_size=$(stat -f%z "$jdoc" 2>/dev/null || stat -c%s "$jdoc")
        if [ "$jdoc_size" -lt "$JAVADOC_MIN_BYTES" ]; then
            echo "ERROR: $module $VERSION -javadoc.jar is only ${jdoc_size} B" \
                 "(< ${JAVADOC_MIN_BYTES} B threshold) — almost certainly empty." >&2
            echo "       This is the 00.74.10 regression: check that" >&2
            echo "       docs/javadoc/jsentinel.css exists and the javadoc tool" >&2
            echo "       did not abort. Re-run the release build, then re-bundle." >&2
            exit 1
        fi
    fi

    module_files=0
    for f in "$dst"/*; do
        case "$f" in
            *.md5|*.sha1|*.sha256|*.sha512) continue ;;
        esac
        generate_checksums "$f"
        module_files=$((module_files + 1))
    done

    echo "Staged $module $VERSION ($module_files primary files + checksums)"
    total_files=$((total_files + module_files))
done

rm -f "$BUNDLE"
(cd "$STAGING" && zip -qr "$BUNDLE" .)
ls -lh "$BUNDLE"

cat <<EOF

Bundle ready: $BUNDLE
Staged $total_files primary files across ${#MODULES[@]} modules (plus signatures and four checksum types each).

Next steps:
  1. Open https://central.sonatype.com/publishing
  2. Click 'Publish Component' / 'Upload a bundle'
  3. Upload the bundle above
  4. Wait for validation, then publish

  Alternative (curl, user-managed deployment):
    curl --request POST \\
      --user "\$CENTRAL_USER:\$CENTRAL_PASSWORD" \\
      --form bundle=@$BUNDLE \\
      'https://central.sonatype.com/api/v1/publisher/upload?name=jCustos-V${VERSION}&publishingType=USER_MANAGED'
EOF
