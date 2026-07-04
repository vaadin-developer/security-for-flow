# jSentinel Feature Overview — Snapshot 2026-07-04 (post V00.79.30 — security hardening)

**Latest release:** V00.79.30 — *Security hardening (28 audit findings)* — published to Maven
Central (deployment `5563686e-8b1e-4d5f-8835-57944eb79317`, tag `v00.79.30` @ `44aed175`).
**40 Central artifacts** — 39 published library modules + the `jSentinel-parent` POM.

---

## New in V00.79.30 — security hardening (28 audit findings)

A maintenance / hardening tick on the 00.79 line — no new feature, no new module. Closes the 28
findings of the 2026-07-02 source-review security audit (0 Critical, 0 High, **4 Medium**, **15
Low**, **9 Info**). Detail: `RELEASE-NOTES-00.79.30.md` + `docs/security/audit/security-audit-2026-07-02.md`
(ClickUp epic `86cahr7vf`, `JS-SEC-001…028`).

### Five themes

| Theme | What changed |
|---|---|
| Session integrity | `LoginView` rotates the HTTP session id on every login regardless of `SessionPolicy` (fixation, JS-SEC-003); a mid-session role/permission drift now terminates the cached subject instead of only deflecting one navigation (JS-SEC-002). |
| Audit PII | The two remaining session-audit paths derive `subjectId` via `SubjectIdResolver`, never `subject.toString()` (JS-SEC-004). |
| JWT / OIDC / DPoP spec-fidelity | Unauthenticated unknown-`kid` JWKS refresh flood throttled (JS-SEC-001); https-only JWKS trust root (JS-SEC-018); unified `crit`-header rejection across alg families (JS-SEC-020); OIDC-layer iss/aud backstop (JS-SEC-007); DPoP `htu` raw-path + `ath` fail-closed (JS-SEC-022/023); back-channel-logout replay protection on by default (JS-SEC-021). |
| Fail-closed defaults | Empty `@RequiresPermission({})` / empty-role evaluators deny (JS-SEC-010/011); CRLF rejected at the step-up + event-decode boundaries (JS-SEC-013/019); propagation caches scope-keyed + bounded (JS-SEC-014/015); on-disk stores owner-only where the platform allows (JS-SEC-016/017); introspection cache capped at token `exp` (JS-SEC-006); CORS lint flags the credentialed `"null"` origin (JS-SEC-025); OIDC logout view clears the local subject by default (JS-SEC-028). |
| Honest guarantees | Corrected over-claimed JavaDoc for the DPoP jti store, the anti-enumeration dummy KDF (mixed-algorithm timing caveat) and the store-backed login-attempt policy (JS-SEC-008/009/012); documented the allow-by-omission authorization model (JS-SEC-024) and the recorded-not-wired REST decision-mapper (JS-SEC-026). |

### Two intentional fail-closed behavior changes

- `RoleBasedAccessEvaluator` with an **empty** required-role set now requires an authenticated
  subject (was "anyone").
- `@RequiresPermission({})` now **denies** (was "any authenticated").

Both only affect mis-configured code; documented in `RELEASE-NOTES-00.79.30.md` § *Statement of
additivity*. `IdTokenValidationError` gains two additive sealed variants (`IssuerMismatch`,
`AudienceMismatch`).

---

## Quality gates (V00.79.30)

- **Every finding** shipped a no-mock real-implementation regression test; every touched module
  `verify` green; full reactor `clean install` green.
- **Standards pass** already-compliant (no items).
- **Exit production-review clean** — 2 findings fixed in-cycle (RF01 JWKS throttle doc, RF02 OIDC
  logout teardown ordering); none deferred.
- **PIT** `jSentinel-core` 84 % (2156/2566); other touched modules non-regressed by construction
  (additive tests only).

---

## Since the last snapshot (V00.77 → V00.79.20)

The snapshot trail lapsed after V00.76.00; the layers added in between (all opt-in modules) —
recorded here at a glance, see each release's notes for detail:

- **V00.77 — OAuth2**: `jSentinel-oauth2` (grants, token introspection RFC 7662) + `-rest` / `-vaadin` adapters.
- **V00.78 — OIDC-RP**: `jSentinel-identity-oidc` (ID-token validation, RP-initiated + back-channel logout) + `-rest` / `-vaadin`; 6 vendor profiles `jSentinel-identity-vendor-{auth0,entra,github,google,keycloak,okta}`.
- **DPoP**: `jSentinel-dpop` (RFC 9449 proof validation, jti replay store).
- **Events**: `jSentinel-events` + `-rest` / `-persistence-eclipsestore` / `-testkit` (security event bus).
- **Token propagation**: `jSentinel-propagation` + `-oidc` / `-processor` (outbound token exchange / client-credentials).
- **Test kit**: `jSentinel-test-oidc`.

Published Central footprint grew from **26** modules (post V00.76.00) to **39 library modules +
`jSentinel-parent`** at V00.79.30.

---

## Roadmap

- Deferred hardening backlog (documented in `RELEASE-NOTES-00.79.30.md`): opt-in deny-by-default
  authorization mode + STRICT un-annotated-route diagnostic (JS-SEC-024), REST decision-mapper /
  error-body auto-wiring (JS-SEC-026), per-outcome KDF cost-floor for the mixed-algorithm timing
  caveat (JS-SEC-009).
- **V00.80.00** — the next feature line (reserved; V00.79.30 was the hardening tick, so 00.80 stays
  feature-only).
