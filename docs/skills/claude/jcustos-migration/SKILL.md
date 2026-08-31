---
name: jcustos-migration
description: Mechanical migration of a consumer project from jSentinel (com.svenruppert.jsentinel:jSentinel-*, packages com.svenruppert.jsentinel, up to V00.81.00) to jCustos (eu.jsentinel:jCustos-*, packages eu.jsentinel.jcustos, V00.81.10+). Use PROACTIVELY when a project depends on any com.svenruppert.jsentinel artifact, imports com.svenruppert.jsentinel.*, references JSentinel* types, jsentinel.* config keys, X-JSentinel-* webhook headers, or when the user mentions "migrate to jCustos", "jSentinel rebrand", "eu.jsentinel", "relocation warning" (Maven prints one when resolving the old coordinates at 00.81.10). Covers the GAV swap, the import/type/config renames, the operator-name mapping table, and the Eclipse-Store fresh-storage break. Wire formats are unchanged — signed envelopes, audit-chain exports and all protocol domain strings stay byte-identical.
---

# jCustos migration (jSentinel → jCustos, V00.81.10)

jSentinel was rebranded to **jCustos** in V00.81.10. Everything renamed;
nothing else changed behaviorally. Apply the steps IN ORDER — each is a
mechanical, whole-project search/replace. Compile after step 3; the
compiler finds every straggler.

## 1. Maven coordinates (GAV swap)

| Old | New |
|---|---|
| `com.svenruppert.jsentinel` (groupId) | `eu.jsentinel` |
| `jSentinel-<module>` (artifactId) | `jCustos-<module>` |
| version `00.81.00` (last jSentinel) | `00.81.10`+ |

The old coordinates carry relocation POMs at `00.81.10` — Maven warns and
redirects, but update explicitly. Order matters in `pom.xml`: replace
`<groupId>com.svenruppert.jsentinel</groupId>` with
`<groupId>eu.jsentinel</groupId>` FIRST, then `jSentinel-` → `jCustos-`.

## 2. Packages and types

1. Imports/FQCNs: `com.svenruppert.jsentinel` → `eu.jsentinel.jcustos`
   (note: package root ≠ groupId — that is intentional).
2. Types: `JSentinel` → `JCustos` (case-sensitive; 172 types incl.
   `@ExperimentalJSentinelApi` → `@ExperimentalJCustosApi`,
   `@JSentinelAutoService` → `@JCustosAutoService`,
   `JSentinelEnforcer` → `JCustosEnforcer`, …).
3. Identifiers you copied from templates: `jSentinel` → `jCustos`.
4. **META-INF/services**: rename every file whose NAME starts with
   `com.svenruppert.jsentinel` (new prefix `eu.jsentinel.jcustos`, new
   type names) AND sweep file CONTENTS — these files have no extension,
   include-filtered sweeps miss them.

## 3. Operator-visible names (hard rename, no aliases)

| Old | New |
|---|---|
| `jsentinel.dev`, `jsentinel.events.bus.enabled` (system properties) | `jcustos.dev`, `jcustos.events.bus.enabled` |
| OTel attributes `jsentinel.*` (14 keys: `jsentinel.envelope.id`, …) | `jcustos.*` |
| Named loggers `com.svenruppert.jsentinel.events` / `….alerts` | `eu.jsentinel.jcustos.events` / `….alerts` |
| Webhook headers `X-JSentinel-Event-Type` / `X-JSentinel-Envelope-Id` | `X-JCustos-Event-Type` / `X-JCustos-Envelope-Id` |
| OAuth2 binding cookie `__Host-JSentinelOAuth2State` | `__Host-JCustosOAuth2State` |
| Wrapper index `META-INF/jsentinel/generated-wrappers.idx` | `META-INF/jcustos/generated-wrappers.idx` |
| Default framework storage subdir `jsentinel-store` | `jcustos-store` |

Update logging configs, dashboards, SIEM parsers and webhook receivers
accordingly.

## 4. What does NOT change (do not touch)

- **Wire formats**: signed event envelopes, the envelope wire JSON,
  `EventType` values, metric names (`security.*`).
- **Protocol domain strings**: `jsentinel-audit-chain/v1`,
  `jsentinel-audit-chain:genesis`, `jsentinel-audit-batch/v1`,
  `jsentinel-audit-event/v1`, `jsentinel-event/canonical-json/v1` —
  old signed data and NDJSON audit exports verify unchanged under jCustos.
- The `jsentinel.eu` domain (docs, default Auth0 claim namespace
  `https://jsentinel.eu/roles`).

## 5. Eclipse-Store storages: fresh start (breaking)

jCustos CANNOT open storages written by jSentinel (persisted FQCNs; no
legacy mappings ship — deliberate). Before upgrading: export what you
need under V00.81.00 (audit chain → NDJSON via `AuditExportService`;
exports stay verifiable forever). Then start jCustos with fresh storage
directories. See `docs/dx/storage-break-v00.81.10.md`.

## 6. Verify

- `grep -rn "com\.svenruppert\.jsentinel\|jSentinel\|JSentinel" src/ pom.xml`
  → zero hits (main + test).
- Build compiles without the Maven relocation warning.
- Round-trip tests (envelope encode/decode, audit verify) green — they
  must not have needed changes beyond imports.
