# jSentinel Feature Overview — Snapshot 2026-08-31 (post V00.81.00 — Session-Lifecycle Integrity)

**Latest release:** V00.81.00 — *Session-Lifecycle Integrity & Critical Security Backlog* —
published to Maven Central (deployment `78c111f6-805f-455f-9ded-a862bdd80d85`,
tag `v00.81.00` @ `c4ed667c`, GPG-signed). **47 Central artifacts** (unchanged set).
GitHub release: https://github.com/vaadin-developer/security-for-flow/releases/tag/v00.81.00

---

## New in V00.81.00 — Session-Lifecycle Integrity & Critical Security Backlog

A focused hardening release, same-day cycle after V00.80.00 shipped. No new
module. Detail: `RELEASE-NOTES-00.81.00.md` (ClickUp plan parent `86cbawy2d`).

| Area | What shipped |
|---|---|
| Session lifecycle (core) | `SweepingSessionStore` decorator — stale ACTIVE records are persisted as `EXPIRED` (one `SessionExpired` audit event, policy precedence preserved) and terminal records past retention (default 30 d) are purged, on every read path, no background thread. Closes the "weeks-old sessions shown as ACTIVE" bug. Audit-reason literals unified in `SessionExpired.REASON_*` (6 producers). |
| Boot diagnostics (dx) | `sessions/no-timeout-policy` — store-backed sessions without any lifetime enforcement now fail a STRICT boot (ERROR in PRODUCTION, INFO in dev). |
| OAuth2 login-CSRF (BL01) | `CallbackStateBinding` hook: `__Host-` cookie binding evaluated fail-closed BEFORE the flow; a rejected callback never consumes the single-use state. Header-injection guards on cookie value AND name. |
| Processor guard (BL02) | Empty security annotations (`@RequiresPermission({})`, blank entries, blank policy names) fail the build with `processing/empty-security-annotation` instead of IAE-ing every call at runtime. |
| Propagation pins (BL03) | Audience/strategy token selection verified + pinned: audience scopes the RFC 8693 mint, caches never cross-serve audiences or subjects. |
| Announced removal | Deprecated `events.rest.EnvelopeWireCodec` delegator deleted (one release after `forRemoval`, migration = import swap, wire format unchanged). |

## Quality gates (V00.81.00)

- Entry gate satisfied by construction (issues were verified audit/review findings);
  in-cycle finder pass over the previously unswept areas: **0 new findings**.
- Standards pass: 1 finding fixed; exit review: **SHIP** (RF-a, RF-b in-cycle).
- **PIT:** core 84 % flat · dx 65 % flat · oauth2-rest 86 % · processor 82 % ·
  rest 94 % · vaadin 80 % · events-rest 69 % · propagation-oidc 63 %.
- V00.79.40-review triage: F1 (lockout-eviction bypass) verified fixed; F2–F10
  lost to a tracker-merge truncation, window covered by subsequent exit-reviewed
  releases.

## Release completeness audit (2026-08-31)

GitHub carries a tag + release page for **every shipped version** (00.51.00,
00.60.00, 00.70.00, v00.72.00 … v00.81.00, plus historic 00.0x-RPM).
**V00.71.00 is documented-but-never-deployed**: release notes and a docs
finalize commit (`e51539d2`) exist, but no Central artifact (`security-core`
jumps 00.70.00 → 00.72.00), no tag, no release — its content shipped with
00.72.00. Left as-is deliberately: a GitHub release without Central artifacts
would suggest availability. Pre-V00.73 artifacts live under the old
`com.svenruppert` groupId (`security-*`); `com.svenruppert.jsentinel` starts
at 00.73.00.

## Roadmap

Next: **V00.81.10 — full rebranding jSentinel → jCustos** (feature-free;
prerequisite `jsentinel.eu` + Central namespace `eu.jsentinel`; project moves
to `Workspaces/jSentinel/jCustos`). Then V00.82.00 (T3 hardening + CSRF,
first release under the new name), V00.83–V00.87 per the versioned backlog.
Backup/restore approach (`issueFullBackup` wiring, `backupTo(Path)`) is
documented on the V00.87 item and can be pulled forward.
