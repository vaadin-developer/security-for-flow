# jCustos V00.81.20 — the edition split

**Theme:** jCustos becomes open core. This repository is now the **Community
Edition** under the EUPL 1.2; nine operations and forensics modules continue as
the commercial **Enterprise Edition**. No feature was removed from the free
edition, no behaviour changed, and no wire format moved. What changed is where
nine modules are published and under which licence.

## The line

**Build and secure is free. Operate and prove is commercial.**

Everything a developer needs to secure an application stays here and stays
complete: the core, all three adapters, the DX layer, compile-time tooling,
Argon2id password hashing, Eclipse-Store persistence, the signed security event
bus, the full OIDC relying-party stack with six vendor profiles, DPoP, token
propagation, four testkits and 15 demos. Nothing is time-limited,
feature-gated or nagware.

The Enterprise Edition answers a different question — what you hand an auditor,
a regulator or a SOC when they ask what your security layer did.

## Moved to the Enterprise Edition

`eu.jsentinel.jcustos.enterprise:jCustos-*`

| Module | Purpose |
|---|---|
| `jCustos-monitoring` | Metrics SPI, `security.*` name catalogue, bus bridge, health indicators |
| `jCustos-audit-integrity` (+ `-testkit`, + `-persistence-eclipsestore`) | Tamper-evident audit chain, verifier, signed batches, re-verifiable NDJSON export |
| `jCustos-events-webhook` | Signed envelopes over HTTPS with retry and backoff |
| `jCustos-events-siem` | CEF, LEEF 2.0, NDJSON formatters |
| `jCustos-events-opentelemetry` | OpenTelemetry logs-bridge export |
| `jCustos-events-rest` | REST/SSE bridge for signed envelopes |
| `jCustos-events-persistence-eclipsestore` | Durable event and replay storage |

They attached to the core purely through SPIs — no community source referenced
one of them, which is why this is a publishing change rather than a rewrite.

## Migration — one line per dependency

Artifact ids, Java packages, class names, wire formats, `EventType` values,
metric names and audit-chain hash domains are **unchanged**. No imports to
rewrite, no stored data to migrate.

```xml
<groupId>eu.jsentinel</groupId>                    <!-- before -->
<groupId>eu.jsentinel.jcustos.enterprise</groupId> <!-- from 00.81.20 -->
```

Add `https://repo.jsentinel.eu/sensitive` and the credentials that come with
the licence. Full instructions:
[`docs/editions/migrating-to-the-enterprise-edition.md`](docs/editions/migrating-to-the-enterprise-edition.md).

Staying free is also an option: the 00.81.10 releases of those modules remain on
Maven Central under the EUPL, and dropping the dependency removes the feature
and nothing else.

## What else changed here

- **`jCustos-bom`** — new. Import it to pin every community artifact from one
  place instead of repeating versions per dependency.
- **Licence headers corrected.** The reactor declared EUPL 1.2 but stamped
  headers saying 1.1, with the retired `idabc/eupl5` URL. All 1469 headers now
  read 1.2. The cause was a plugin limitation, not an oversight: the header
  plugin ships no EUPL 1.2 template.
- **Dead dependencies removed.** `jCustos-jwt`, `jCustos-oauth2` and
  `jCustos-identity-oidc` declared `jCustos-events` at compile scope without
  using a single line of it. Removing the declarations makes the edition
  boundary honest — the event bus stays free on its own merits.
- **Contributions now require a CLA** ([`CLA.md`](CLA.md)). The grant is
  non-exclusive — contributors keep every right in their own work — and the
  project commits in return to keeping every contribution permanently available
  under a free licence. Obvious fixes are exempt.
- The reactor parent is now `jCustos-community-parent`. Module artifact ids are
  unchanged, so consumers see no difference.

## Delivery mechanics

Development moves to **https://git.jsentinel.eu/jSentinel/jCustos-community**;
GitHub is a push mirror of it. Pull requests on GitHub are welcome and are
applied upstream, then carried back by the mirror — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

Artifacts: Maven Central plus `https://repo.jsentinel.eu/releases`.

## Verification

- Community 6562 tests, Enterprise 450 tests — no failures, no errors.
- File parity across the split: 1806 + 139 = 1945 sources, byte-for-byte the
  same set as before. Verbatim migration, nothing regenerated.
- The boundary is a test in both directions: community code may not name an
  enterprise package, enterprise code may not reach into a community `internal`
  package. Both were verified to fail when a violation is introduced.
- The enterprise reactor carries 84 commits of real history back to V00.75.00.

## Roadmap

Enterprise licence gating — a signed, offline-verifiable licence file checked at
bootstrap — is planned for V00.82.00.
