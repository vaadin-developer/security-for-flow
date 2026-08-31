# jSentinel V00.81.00 — Session-Lifecycle Integrity & Critical Security Backlog

**Theme:** a focused hardening release — session records finally age (EXPIRED
transition, retention purge), the highest-priority open audit findings (Tier 1
+ Tier 2) are closed, and the wire-codec delegator removal announced in
V00.80.00 is executed. No new module, no new feature surface.

## Themes

1. **Session-lifecycle integrity** — the reported bug "admin views show
   weeks-old sessions as ACTIVE" is closed: the new `SweepingSessionStore`
   decorator persists the policy-true state on every read and implements the
   retention promise of the `SessionStore` contract; a STRICT/PRODUCTION boot
   now flags store-backed sessions configured without any lifetime enforcement.
2. **OAuth2 login-CSRF (BL01, CWE-352)** — the REST callback handler binds the
   single-use `state` to the user-agent fail-closed via the new
   `CallbackStateBinding` hook (`__Host-` cookie, constant-time compare).
3. **Processor compile guard (BL02, CWE-863)** — empty security annotations
   (`@RequiresPermission({})`, …) now fail the build with
   `processing/empty-security-annotation` instead of only failing every call
   at request time.
4. **Propagation selection pinned (BL03, CWE-522)** — the audience/strategy
   token-selection chain is verified and pinned by regression tests: no token
   ever goes to the wrong outbound audience, caches never cross-serve.
5. **Announced removal** — the deprecated `events.rest.EnvelopeWireCodec`
   delegator is gone (one release after `forRemoval = true, since = "00.80.00"`).

## Statement of additivity

Everything in this release is additive **except**:

- **Removal (announced):** `com.svenruppert.jsentinel.events.rest.EnvelopeWireCodec`
  (deprecated delegator) — see *Migrations* below. The authoritative codec
  `com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec` and the wire format
  are unchanged.
- **STRICT/PRODUCTION boot finding:** store-backed sessions without
  `.timeout(...)` / `.absoluteLifetime(...)` / `.policy(...)` now raise
  `sessions/no-timeout-policy` (ERROR — STRICT fails the boot, PRODUCTION
  surfaces the finding, dev modes stay INFO). Affects only setups whose
  sessions silently never expired.
- **Compile-time rejection of empty security annotations:** code that
  previously compiled and then failed *every* call with an
  `IllegalArgumentException` now fails the build. Misconfigured code only.
- The pre-V00.81 two-argument `OAuth2CallbackHandler` constructor keeps its
  behavior (unbound) and now logs the open login-CSRF surface once
  (`oauth2/state-unbound`).

## Headline change

Before (V00.80.00) — records stayed `ACTIVE` forever unless an admin clicked
*Revoke*:

```java
SessionStore store = new InMemorySessionStore();
// … weeks later: findAll() still lists closed browsers as ACTIVE
```

After (V00.81.00) — wrap the store once; every read shows and persists the
policy-true state:

```java
SessionStore store = new SweepingSessionStore(
    new InMemorySessionStore(),
    new TimeoutSessionPolicy<>(config, clock, audit));
// stale ACTIVE → persisted EXPIRED + one SessionExpired audit event
// terminal records past retention (default 30 days) → purged
```

And the callback side of the OAuth2 login flow:

```java
// start side: bind the state to this browser
response.header("Set-Cookie", CallbackStateBinding.hostCookieHeader(state));
// callback side: fail-closed binding BEFORE the flow runs
new OAuth2CallbackHandler(flow, sink, CallbackStateBinding.hostCookie());
```

## What's new in detail

| Area | Change |
|---|---|
| `jSentinel-core` (session) | `SweepingSessionStore` decorator: per-record `SessionPolicy.evaluate(...)` on every read path; stale ACTIVE → persisted `EXPIRED` + exactly one `SessionExpired` (reason precedence identical to `TimeoutSessionPolicy`); terminal records past `lastActivityAt + retention` (default 30 d) deleted. No background thread. Audit-reason literals got a single home: `SessionExpired.REASON_IDLE_TIMEOUT` / `REASON_ABSOLUTE_LIFETIME` (6 producers migrated). |
| `jSentinel-dx` | New bootstrap finding `sessions/no-timeout-policy` (JS-SEC-035 follow-up, JS-SEC-056 gating pattern): ERROR in STRICT/PRODUCTION, INFO in dev modes. |
| `jSentinel-oauth2-rest` | `CallbackStateBinding` hook (`hostCookie()`, `hostCookieHeader(...)` with header-injection guards on value AND name, `unbound()`); `OAuth2CallbackHandler` evaluates the binding fail-closed before the flow — a rejected callback does **not** consume the single-use state; status ints migrated to the `HttpStatus` enum. |
| `jSentinel-processor` | `processing/empty-security-annotation` compile ERROR for empty value arrays, blank entries and blank `@RequiresPolicy` names (R031 pattern). `PropagateTokenProcessor` audited: the empty-advice skip is the documented advisor contract — no change. |
| `jSentinel-propagation-oidc` | `AudienceSelectionRegressionTest`: audience travels into the RFC 8693 exchange and scopes the mint; cache serves same (subject, audience) only; subjects never share entries; blank audience omits the parameter. |
| `jSentinel-events-rest` | Deprecated `EnvelopeWireCodec` delegator + its byte-identity pin test removed; zero references remain reactor-wide. |

## What V00.81.00 does NOT do

- No new modules, SPIs or wire-format changes.
- No automatic session-timeout default (the full profile-default DX remains
  backlog — this release only makes the gap visible at boot).
- No adapter-side EXPIRED writes at the invalidate points: there is
  deliberately no global session-store registry, and the sweep produces the
  identical state on the next read with the same policy.
- T3/T4 backlog (BL04/05/07/08/09/10/11/12) stays versioned for V00.82/V00.83.

## Migrations

**`EnvelopeWireCodec` (removal executed):** replace
`com.svenruppert.jsentinel.events.rest.EnvelopeWireCodec` /
`…events.rest.EventWireException` imports with
`com.svenruppert.jsentinel.events.wire.*`. `encode`/`decode` signatures and the
wire format are byte-identical; consumers needing only the codec can depend on
`jSentinel-events` instead of `jSentinel-events-rest`. Do not reference
`WireJson` (package-private).

**Session stores:** wrap the concrete store once at wiring time in
`SweepingSessionStore` (see headline). Admin views (`SessionManagementView`)
need no change — `findAll()` now returns the policy-true state.

**OAuth2 REST callback:** switch to the three-argument
`OAuth2CallbackHandler` constructor with `CallbackStateBinding.hostCookie()`
and emit `hostCookieHeader(state)` on the start side. Integrations that bind
state themselves keep the two-argument constructor (now logged once).

## Mutation coverage

| Module | V00.80.00 baseline | V00.81.00 measured | Status |
|---|---|---|---|
| jSentinel-core | 84 % | 84 % (2253/2680) | ✅ flat |
| jSentinel-oauth2-rest | — | 86 % (50/58) | ✅ new baseline |
| jSentinel-processor | — | 82 % (72/88) | ✅ new baseline |
| jSentinel-dx | 65 % | 65 % (470/719) | ✅ flat |
| jSentinel-rest | — | 94 % (103/109) | ✅ new baseline |
| jSentinel-vaadin | — | 80 % (267/333) | ✅ new baseline |
| jSentinel-events-rest | — | 69 % (72/104) | ✅ new baseline (delegator + pin test removed) |
| jSentinel-propagation-oidc | — | 63 % (106/167) | ✅ new baseline (tests only added) |

Acceptance threshold held: no module fell more than 3 pp under its previous
baseline (both known baselines are flat).

## Acceptance summary

- ✓ Entry gate: the cycle's issues ARE verified production-review/audit
  findings; the in-cycle finder pass covered the previously unswept areas
  (OAuth2/OIDC redirect glue, propagation core, processors) — 0 new findings.
- ✓ Every fix ships a no-mocks regression test against the real
  implementation (real flow + HttpServer stubs, real stores, real policies,
  fixed clocks, compile-testing for the processor).
- ✓ Standards pass: 1 finding (audit-reason literal home), fixed.
- ✓ Exit review: SHIP — RF-a (cookie-name header-injection guard) and RF-b
  (documented sweep race) fixed in-cycle.
- ✓ Full reactor green with tests.
- ✓ V00.79.40-review triage: F1 (lockout-eviction bypass) verified fixed in
  current code; F2–F10 detail lost to a tracker-merge truncation, window
  covered by two subsequent exit-reviewed releases.

## Roadmap

Next: **V00.81.10 — full rebranding jSentinel → jCustos**
(`eu.jsentinel.jcustos`, `jCustos-*`, project moves to
`Workspaces/jSentinel/jCustos`; feature-free cycle, prerequisite: Central
namespace verification for `eu.jsentinel`). Then V00.82.00 (T3 hardening +
CSRF) as the first release under the new name.

---

Concept: `Konzept-V00.81.00.md` · Plan: ClickUp parent `86cbawy2d` ·
Predecessor: `RELEASE-NOTES-00.80.00.md`
