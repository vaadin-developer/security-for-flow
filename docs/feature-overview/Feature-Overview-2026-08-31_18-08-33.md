# jCustos Feature Overview — Snapshot 2026-08-31 (post V00.81.10 — the rebranding)

**Latest release:** V00.81.10 — *the jSentinel → jCustos rebranding* — published to
Maven Central as **`eu.jsentinel:jCustos-*:00.81.10`** (deployment
`52d67418-188f-4c93-830a-87b7f888212a`, tag `v00.81.10` @ `5d0ad389`, GPG-signed).
A second deployment (`04727178-0a8d-48b0-850e-7a7163629fb1`) published **47
relocation POMs** under the old `com.svenruppert.jsentinel:jSentinel-*`
coordinates — Maven redirects and prints the migration message.
GitHub release: https://github.com/vaadin-developer/security-for-flow/releases/tag/v00.81.10

---

## What V00.81.10 is

A feature-free, behavior-free full rename executed in seven green waves
(each landed with a full reactor + tests): packages
`com.svenruppert.jsentinel` → `eu.jsentinel.jcustos` (112 trees), 172
`JSentinel*` → `JCustos*` types, operator names → `jcustos.*`, 56 module
directories → `jCustos-*`/`demo-jcustos-*`, groupId → `eu.jsentinel`,
12 integration skills re-released as `jcustos-*` plus a new
`jcustos-migration` consumer skill. Wire formats, protocol domain strings,
`EventType` values and the `security.*` metric catalog stayed byte-identical —
old signed envelopes and NDJSON audit exports verify unchanged.

**Breaking**: everything consumer-visible renamed (see the mapping table in
`RELEASE-NOTES-00.81.10.md`), plus the Eclipse-Store fresh-storage break
(`docs/dx/storage-break-v00.81.10.md` — no legacy type mappings, deliberate).

## Quality gates

- Full reactor green with tests after every rename wave; golden-value hash
  pins green throughout; static-analysis sample green after the RF-1 fix.
- Exit review SHIP — the two silent-breakage classes a plain rename sweep
  misses, both caught and fixed in-cycle: extensionless META-INF/services
  CONTENTS, and SpotBugs exclude patterns written as escaped-dot REGEXES.

## Remaining step

**P008 (post-deploy):** move the project to
`/Users/svenruppert/Workspaces/jSentinel/jCustos`, rename the GitHub
repository, migrate the Claude project state (memory path is bound to the
old directory).

## Roadmap

**V00.82.00 — hardening rest (T3) & CSRF** is next: the first feature
release under the jCustos name (BL04/05/07/08/09 + CSRF hardening), then
V00.83–V00.87 per the versioned backlog. Backup/restore
(`backupTo(Path)` via Eclipse Store `issueFullBackup`) is documented on
the V00.87 item and can be pulled forward.
