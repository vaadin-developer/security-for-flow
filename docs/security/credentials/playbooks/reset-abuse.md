# Playbook — Password Reset Abuse

Status: draft — V00.71.00
CWE: CWE-307 (Improper Restriction of Repeated Authentication
Attempts), CWE-640 (Weak Password Recovery Mechanism),
CWE-203 (Observable Discrepancy)

## Trigger

- `AbusePatternMonitor` raises a `RESET_ABUSE` signal.
- Audit shows an elevated rate of
  `PasswordResetRequested` events against a single account or a
  set of accounts.
- Operations / support sees an unusual rate of "I didn't request
  this" complaints.

## Pre-conditions

- The deployment uses `PasswordResetService` from
  `security-core` (V00.71.00 selector/verifier model).
- `AbuseDetectionService` and `AbusePatternMonitor` are wired
  into the reset flow.

## Response

### 1. Confirm the signal

- Query the audit sink for `PasswordResetRequested` and
  `RateLimitExceeded` events.
- Confirm the cardinality and time window. A burst of 5 requests
  for the same account within 60 minutes is the default
  threshold; deployments may have tightened it.

### 2. Throttle

- `AbuseDetectionService` already returns
  `AbuseDecision.Block` once the per-username
  `RESET_REQUEST` window count crosses the threshold.
- The block is timed (`retryAfter`). The framework does not
  surface this to end users beyond a generic message — that is
  the consuming application's responsibility. **Do not** add a
  detail field that confirms "your account is rate-limited" —
  it would be a user-enumeration channel (CWE-203).

### 3. Invalidate outstanding tokens

If the abuse pattern suggests credential-stuffing of reset
tokens themselves:

- The reset token table uses the selector / verifier split. The
  selector is the only part visible to the client; the verifier
  is a SHA-256 digest stored at rest.
- Operators can purge the reset-token table for affected users
  through the consuming application's admin path. The framework
  does not expose a bulk-invalidation API — it is intentional
  scope reduction.

### 4. Decide on credential rotation

- A high-confidence reset-abuse signal does **not** imply the
  account is compromised. Do not auto-rotate.
- If account-level compromise is suspected, run the per-account
  `MUST_CHANGE` transition via the lifecycle service. For
  service-wide concerns, see `pepper-compromise.md` or
  `algorithm-compromise.md`.

## Rollback boundary

- A throttle decision is automatically reversible — the next
  window expiry restores normal behaviour.
- A `MUST_CHANGE` transition is **not** automatically reversible.

## Operator checklist

- [ ] Confirm the `AbusePatternMonitor` signal from audit.
- [ ] Confirm throttling is active for the affected scope.
- [ ] Decide whether token bulk-invalidation is warranted.
- [ ] Avoid distinct user-facing messages that reveal throttle
      state (CWE-203, CWE-209).
- [ ] Post-incident review.

## What the framework does not do

- It does **not** notify end users that they were targeted.
- It does **not** silently extend the throttle window.
- It does **not** auto-rotate credentials.
- It does **not** publish or persist client IP addresses in
  abuse-pattern signals — those carry aggregates only.
