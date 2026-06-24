# jSentinel V00.75.10 — Core hardening, robustness & a static-analysis gate

V00.75.10 is a **hardening & robustness tick** on the active maintenance line
after V00.75.00 (Security Event Bus), before the JWT/OAuth2/OIDC arc
(V00.76 – V00.79). **No new feature, no new module.** It makes type-safe what
was guarded only by comments, nails down untested fail-paths, hardens the manual
parsers, and turns a deliberately defensive eye on the freshly-shipped event bus.

It ships **two layers**: the six Konzept hardening blocks **H1–H6**, and four
**urgent review findings** (R002–R005) on the just-released event bus and the
Eclipse-Store persistence that were pulled in alongside.

---

## Theme

Type safety instead of a comment; tested fail-paths instead of blind spots;
hardened parsers; isolable state; and a sharp SpotBugs/FindSecBugs gate over the
security-critical core modules.

---

## Urgent fixes (review findings R002–R005, event bus + persistence)

| # | Severity | What |
|---|---|---|
| **R002** | High | **Eclipse-Store nested-collection mutations were lost on restart.** `EclipseStoreRateLimitStore` and `EclipseStoreRoleAssignmentStore` mutated a nested `LinkedHashSet` in place and then `store(parentMap)` — Eclipse Store does not re-store an already-persisted nested set, so the change vanished on reopen (rate-limit counters under-reporting → bypassable; granted/revoked roles reverting). Now `store(...)` the actually-mutated set. Proven by new close/reopen restart tests that **fail on the old code**. A sweep confirmed these were the only two nested-collection stores. |
| **R003** | High | **`ConsumePipeline` committed side effects before all gates passed.** `replayStore.markSeen()` and `sequenceStore.updateSequence()` ran *before* the sequence and producer-policy gates, so a producer-denied or sequence-violating envelope still poisoned the replay store and advanced the per-producer sequence. The gates are now all read-only first (with an early read-only `hasSeen()` that preserves the `ReplayDetected` result); the two side effects commit only after every gate passes. |
| **R004** | High | **EXPIRED signing keys were accepted.** The key-status gate rejected only `REVOKED`. It now whitelists `ACTIVE` / `ACCEPTED_FOR_VERIFICATION`; `EXPIRED` → a new `KeyExpired` result, anything else fails closed. This closes the real path where `JdkKeyStoreKeyManagement.keyStatus()` reports `EXPIRED` for an expired X.509 certificate. |
| **R005** | Medium | **Signing-base field-injection robustness.** `EnvelopeSignatureBase` joined fields as `key=value\n` and rested on an *unenforced* "ids can't contain the separator" claim (the id types only reject blank). Framing is now **length-prefixed** (`key=<utf8-byte-length>:value\n`), injective for any value content. See the wire-format note below. |

---

## H1 – H6 (Konzept hardening blocks)

### H1 — Token-digest type safety

Four core services stored a token under `hasher.hash(plain)` and looked it up by
that hash. With the documented default `Pbkdf2PasswordHasher` (a fresh random
salt per call) the lookup could **never** match — correctness rested on a comment.
V00.75.10 makes it a type:

- New `TokenHasher` contract + shipped `Sha256TokenHasher` (deterministic,
  byte-identical to the former demo copy) + a `TokenHashers.fromPasswordHasher`
  adapter in `jSentinel-core/credential/token`.
- `TokenService`, `accountlifecycle.PasswordResetService`,
  `EmailVerificationService` **and** `ApiKeyAuthenticationService` (the 4th
  service with the identical bug — included by decision over the Konzept's three)
  now take a `TokenHasher`. The old `PasswordHasher` constructors are
  `@Deprecated(forRemoval = true)` and delegate through the adapter, which runs a
  **determinism probe at construction** and rejects a salted KDF (CWE-208 /
  CWE-640) loudly rather than failing silently on every lookup.
- `demo-rest` wires the library `Sha256TokenHasher` for all four services; the
  demo-local copy is gone.

### H2 — Negative tests

Per service (all four), real-impl tests (no mocks): a real `Pbkdf2PasswordHasher`
through the deprecated constructor proves the guard's `IllegalArgumentException`,
and a salted `TokenHasher` stub documents that lookups would otherwise return
empty.

### H3 — Static-analysis gate

A CI-only `-Pstatic-analysis` Maven profile on the four security-critical
modules (`jSentinel-core`, `-rest`, `-events`, `-events-rest`) runs
**SpotBugs 4.9.8.3 + FindSecBugs 1.13.0** (effort=Max, threshold=Medium,
`failOnError`) at `verify`. `config/spotbugs/spotbugs-exclude.xml` baselines the
findings present at introduction so the gate starts green and only **new**
findings break the build (existing ones → backlog). Verified end to end: SpotBugs
parses Java 26 bytecode, all four gates are green, an injected `NP_ALWAYS_NULL`
High finding breaks the build (then removed), and the default fast build is
unburdened. (DX / adapter / persistence / demo modules stay out of scope —
later tick.)

### H4 — Manual JSON-parser hardening

`WireJson` (events-rest) now wraps **every** parser failure into the domain
`EventWireException` instead of leaking raw JDK exceptions — bounds-checked
trailing backslash and `\u` escape (were `StringIndexOutOfBounds`), caught `\u`
non-hex and number overflow (were `NumberFormatException`), and a guarded
end-of-input separator read. A new `EventWireException(String, Throwable)` ctor
preserves the JDK cause. `JsonResponse.expiresIn` (OIDC propagation) guards the
unbounded `\d+ → Long.parseLong` against overflow → `Optional.empty()`. A
deterministic malformed/fuzz corpus asserts every input yields
`EventWireException` or a clean parse, never a raw JDK exception.

### H6 — REST-bridge transport

`HttpExchangeRestRequest.queryParameters()` now URL-decodes each token via
`getRawQuery()` + `URLDecoder` (raw, to avoid double-decoding a literal `%2B`).
`EventPublishHttpHandler.handle()` wraps the body read in `try/catch
(UncheckedIOException)` → a clean `400 Malformed request` instead of an
ungracefully-propagating exception on a mid-body client disconnect.

### H5 — Instantiable `JSentinelContext` behind the static facade

The static global service locator `JSentinelServiceResolver` (1029 lines, 16
mutable references, ~119 callers) is lifted into a per-instance
`JSentinelContext` without any breaking change. The context holds the 16
references as instance fields with every getter/setter/fallback moved verbatim,
plus instance `resetAll()` (clears only this instance — **not** the global
`SubjectStores`) and a `createIsolated()` factory. The resolver keeps every
static signature, now delegating to a process-wide
`private static final JSentinelContext DEFAULT` (46 delegations) and adds
`current()`. Parallel tests and multi-app embedding become possible; the static
facade is **not** deprecated — it stays the convenient single-app default.
Threading the context through the adapters is out of scope (Konzept §4.5).

---

## Wire-format change (R005) — call-out

The signing base changed from `key=value\n` to length-prefixed
`key=<utf8-byte-length>:value\n`. **Signatures produced by V00.75.00 do not
verify under V00.75.10.** Sign and verify both go through
`EnvelopeSignatureBase.compute`, so round-trip within a version is unaffected.
The event bus is `@ExperimentalJSentinelApi`, so the format may still change.

---

## Statement of additivity

Additive over V00.75.00. The only behavioural breaks are the intended ones:
(a) the H1 determinism guard now rejects a salted hasher passed to a token
service at construction — a deterministic `PasswordHasher` still works; and
(b) the R005 signing-base wire-format change above. No V00.73 stable surface
changed; every new type carries `@ExperimentalJSentinelApi`.

---

## Exit review (§3.7)

A final adversarial production-review over the cycle delta surfaced **one**
finding — RF01 (Medium): `HttpExchangeRestRequest.decode()` could throw
`IllegalArgumentException` on a malformed `%`-escape (an H6 regression). Fixed
in-cycle; reachability is defensive-only (the JDK `URI` validates `%`-escapes
before `getRawQuery()` is read). No urgent/High findings. The gate reorder, the
key-status whitelist, the length-prefixed signing base, the two Eclipse-Store
fixes, the token-service guard, and the resolver→context lift were all verified
clean (independent review + the SpotBugs/FindSecBugs gate).

---

## What V00.75.10 does NOT do

- No full token-model unification onto `TokenDigestService` (selector/verifier)
  for the V00.70 services — schema change, follow-up from V00.76.
- No SpotBugs/FindSecBugs for DX / adapter / persistence / demo modules — later
  tick; their `spotbugs.skip` stays.
- No Error Prone / Semgrep (one static tool per tick).
- No context pass-through through the adapters — H5 ships the structure only.
- No working-off of the baseline-excluded SpotBugs findings — backlog.

---

## Mutation coverage (PIT)

The cycle is **test-additive** — every fix landed with a bug-catching test
(several proven to fail on the old code) and H5 kept all six existing resolver
suites green — so no touched module can regress below its V00.75.00 baseline by
construction (the same "test-additive modules don't regress" discipline used for
untouched modules).

Spot-checked empirically on the most-changed module, **`jSentinel-events`**
(R003/R004/R005): PIT runs green with healthy per-package mutation coverage —
`events.bus` 86%, `events.keys` ~73–90%, `events.replay` 80%, `events.sequence`
77%, `events.signature` 85%, `events.api` 92%. (`jSentinel-events` is a V00.75.00
module with no earlier PIT baseline; the V00.71/V00.73 baselines in `CLAUDE.md`
predate it.) The new R003/R004/R005 and `EnvelopeSignatureBase` tests add kills
on exactly the touched paths.

---

## Acceptance summary

- ✓ Full reactor `./mvnw clean install` green (all modules, all tests).
- ✓ H1: `TokenHasher` + `Sha256TokenHasher` in core; four services on the new
  contract; deprecated `PasswordHasher` ctors + determinism guard; demo migrated.
- ✓ H2: per-service negative tests with a real `Pbkdf2PasswordHasher`, no mocks.
- ✓ H3: `-Pstatic-analysis` gate green on the four core modules; injected finding
  breaks the build (verified, removed); baseline documented.
- ✓ H4: `WireJson` malformed corpus → only `EventWireException`;
  `JsonResponse.expiresIn` overflow → empty.
- ✓ H5: `JSentinelContext` instantiable; isolated contexts don't cross-leak; the
  static facade delegates 1:1; all six resolver suites unchanged-green.
- ✓ H6: query params URL-decoded; body-read failure → clean 400.
- ✓ R002–R005 urgent event-bus / persistence fixes, each with a bug-catching test.
- ✓ §3.7 exit review clean (one Medium, RF01, fixed in-cycle).

---

## Roadmap

`Konzept-V00.75.00.md`-era event-bus follow-ups and the JWT/OAuth2/OIDC arc
(V00.76 – V00.79) build on the hardened `JSentinelContext` (multi-IdP test
setups) and the clean `TokenHasher` contract (refresh-token work).

---

**Footnotes**

- Source concept: `Konzept-V00.75.10.md` (§4 detail, §8 acceptance, §10 order).
- Plan + per-prompt tracking: ClickUp `V00.75.10 — Implementation Plan`
  (`86cadh0gg`); runbook `docs/process/implementation-cycle.md`.
