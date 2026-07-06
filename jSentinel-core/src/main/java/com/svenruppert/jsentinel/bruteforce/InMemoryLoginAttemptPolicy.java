/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.bruteforce;

import com.svenruppert.jsentinel.audit.BruteForceLimitReached;
import com.svenruppert.jsentinel.audit.LoginFailed;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.util.CapacityBound;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory {@link LoginAttemptPolicy} suitable for single-node demos
 * and small deployments.
 * <p>
 * Counts failures per (username, clientAddress) pair plus an additional
 * username-only counter so an attacker cannot cycle clients to evade the
 * combined counter. Username and clientAddress are normalised
 * (lower-cased + trimmed) before use as map keys.
 * <p>
 * After {@link LoginAttemptConfiguration#failureThreshold()} failures
 * inside {@link LoginAttemptConfiguration#window()} the key is locked
 * for {@link LoginAttemptConfiguration#initialLockout()}. Repeated
 * breaches double the lockout up to
 * {@link LoginAttemptConfiguration#maxLockout()} (progressive backoff).
 * A successful {@link #recordSuccess(LoginAttemptContext) recordSuccess}
 * resets the combined counter; the username-only counter is reset on
 * the next successful login by the same user even from a different
 * client.
 *
 * <h2>Audit</h2>
 *
 * <p>The policy emits audit events through the
 * {@link JSentinelServiceResolver#securityAuditService() resolved}
 * {@link JSentinelAuditService}:
 *
 * <ul>
 *   <li>{@link LoginFailed} on every
 *       {@link #recordFailure(LoginAttemptContext) recordFailure}</li>
 *   <li>{@link BruteForceLimitReached} the first time a key crosses the
 *       failure threshold</li>
 * </ul>
 *
 * <p>Audit-sink failures are swallowed — they must never break the
 * security flow that emitted them.
 */
public final class InMemoryLoginAttemptPolicy implements LoginAttemptPolicy {

  private final LoginAttemptConfiguration config;
  private final Clock clock;
  private final JSentinelAuditService auditService;
  private final int maxEntries;
  private final ConcurrentMap<String, State> byCombinedKey = new ConcurrentHashMap<>();
  private final ConcurrentMap<String, State> byUsername = new ConcurrentHashMap<>();

  /** Defaults — suitable for single-node demos. */
  public InMemoryLoginAttemptPolicy() {
    this(LoginAttemptConfiguration.defaults(), Clock.systemUTC(), null);
  }

  /**
   * @param config       throttling thresholds
   * @param clock        time source — fixed clocks make testing deterministic
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link JSentinelServiceResolver} on each event
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptConfiguration config,
                                    Clock clock,
                                    JSentinelAuditService auditService) {
    this(config, clock, auditService, CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * JS-SEC-048 (CWE-770): additionally bound the per-key maps. Both maps are keyed on
   * attacker-controlled username / client address, so a spray of distinct throwaway usernames would
   * otherwise grow the heap without limit (a one-shot key at {@code failures=1} is reclaimed only by
   * a valid {@code recordSuccess}). When a map is at capacity, a new key evicts a non-locked entry —
   * never an in-force lockout (the RF01 invariant), so the throttle cannot be sprayed away.
   *
   * @param maxEntries per-map key cap (shared default {@link CapacityBound#DEFAULT_MAX_ENTRIES})
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptConfiguration config,
                                    Clock clock,
                                    JSentinelAuditService auditService,
                                    int maxEntries) {
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.auditService = auditService;
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  /** Package-visible for tests: number of tracked combined-key entries (JS-SEC-048 bound). */
  int trackedCombinedKeyCount() {
    return byCombinedKey.size();
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);

    State combined = byCombinedKey.get(combinedKey(context));
    LoginAttemptDecision combinedDecision = lockoutDecision(combined, now);
    if (combinedDecision != null) {
      return combinedDecision;
    }

    State user = byUsername.get(usernameKey(context));
    LoginAttemptDecision userDecision = lockoutDecision(user, now);
    if (userDecision != null) {
      return userDecision;
    }
    return LoginAttemptDecision.allowed();
  }

  private static LoginAttemptDecision lockoutDecision(State state, Instant now) {
    if (state == null || !state.isLocked(now)) {
      return null;
    }
    Duration remaining = Duration.between(now, state.lockedUntil());
    if (remaining.isNegative()) {
      remaining = Duration.ZERO;
    }
    return LoginAttemptDecision.lockedOut(remaining, state.totalFailuresObserved());
  }

  @Override
  public void recordSuccess(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    byCombinedKey.remove(combinedKey(context));
    byUsername.remove(usernameKey(context));
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);

    State combined = recordOn(byCombinedKey, combinedKey(context), now);
    State user = recordOn(byUsername, usernameKey(context), now);

    auditLoginFailed(context);
    State justLocked = combined.justLocked() ? combined : user.justLocked() ? user : null;
    if (justLocked != null) {
      auditBruteForceLimitReached(context, justLocked, now);
    }
  }

  private State recordOn(ConcurrentMap<String, State> map, String key, Instant now) {
    enforceBound(map, key, now);
    return map.compute(key, (k, current) -> {
      State state = current == null ? State.empty() : current.expireOldFailures(now, config.window());
      return state.addFailure(now, config);
    });
  }

  /**
   * JS-SEC-048 (CWE-770) + RF01 invariant: when {@code map} is at capacity and {@code incomingKey}
   * is new, evict entries that are NOT currently locked, back under the bound. An in-force lockout
   * is never evicted (a distinct-username spray must not push a victim's lock out of the map); if
   * every remaining entry is a live lockout a transient soft overshoot is accepted — locks are
   * time-bounded and self-reclaim.
   */
  private void enforceBound(ConcurrentMap<String, State> map, String incomingKey, Instant now) {
    if (map.size() < maxEntries || map.containsKey(incomingKey)) {
      return;
    }
    var it = map.entrySet().iterator();
    while (map.size() >= maxEntries && it.hasNext()) {
      var entry = it.next();
      if (entry.getKey().equals(incomingKey) || entry.getValue().isLocked(now)) {
        continue;
      }
      it.remove();
    }
  }

  private String combinedKey(LoginAttemptContext context) {
    return normalise(context.username()) + "|" + normalise(context.clientAddress());
  }

  private String usernameKey(LoginAttemptContext context) {
    return normalise(context.username());
  }

  private static String normalise(String value) {
    return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
  }

  private void auditLoginFailed(LoginAttemptContext context) {
    JSentinelAuditService sink = sink();
    try {
      sink.publish(new LoginFailed(
          Instant.now(clock),
          context.username() == null ? "" : context.username(),
          context.clientAddress(),
          "Credentials rejected"));
    } catch (RuntimeException auditFailure) {
      // never block a security decision because the audit sink failed
    }
  }

  private void auditBruteForceLimitReached(
      LoginAttemptContext context, State state, Instant now) {
    JSentinelAuditService sink = sink();
    Duration lockoutRemaining = state.lockedUntil() == null
        ? Duration.ZERO
        : Duration.between(now, state.lockedUntil());
    if (lockoutRemaining.isNegative()) {
      lockoutRemaining = Duration.ZERO;
    }
    try {
      sink.publish(new BruteForceLimitReached(
          Instant.now(clock),
          context.username() == null ? "" : context.username(),
          context.clientAddress(),
          state.totalFailuresObserved(),
          lockoutRemaining));
    } catch (RuntimeException auditFailure) {
      // never block a security decision because the audit sink failed
    }
  }

  private JSentinelAuditService sink() {
    return auditService != null
        ? auditService
        : JSentinelServiceResolver.securityAuditService();
  }

  // ── State ─────────────────────────────────────────────────────

  /**
   * Per-key throttling state. Immutable so it can be CAS-updated through
   * {@link ConcurrentMap#compute(Object, java.util.function.BiFunction)}.
   * {@link #totalFailuresObserved()} is the lifetime failure count for
   * the key — what the {@link LoginAttemptDecision.LockedOut#failedAttempts()}
   * field reports.
   */
  private record State(int failures, Instant firstFailureAt, Instant lockedUntil,
                       int lockoutLevel, boolean justLocked, int totalFailuresObserved) {

    static State empty() {
      return new State(0, null, null, 0, false, 0);
    }

    boolean isLocked(Instant now) {
      return lockedUntil != null && now.isBefore(lockedUntil);
    }

    /**
     * If the failure window has elapsed without breach, drop old failures.
     * Lockout state is preserved — callers check {@link #isLocked(Instant)}.
     */
    State expireOldFailures(Instant now, Duration window) {
      if (firstFailureAt != null && now.isAfter(firstFailureAt.plus(window))) {
        return new State(0, null, lockedUntil, lockoutLevel, false, totalFailuresObserved);
      }
      return new State(failures, firstFailureAt, lockedUntil, lockoutLevel, false,
          totalFailuresObserved);
    }

    State addFailure(Instant now, LoginAttemptConfiguration config) {
      int nextFailures = failures + 1;
      Instant first = firstFailureAt == null ? now : firstFailureAt;
      int nextTotal = totalFailuresObserved + 1;

      if (nextFailures >= config.failureThreshold()) {
        int level = lockoutLevel + 1;
        Duration duration = lockoutDuration(level, config);
        Instant until = now.plus(duration);
        return new State(0, null, until, level, true, nextTotal);
      }
      return new State(nextFailures, first, lockedUntil, lockoutLevel, false, nextTotal);
    }

    private static Duration lockoutDuration(int level, LoginAttemptConfiguration config) {
      Duration initial = config.initialLockout();
      Duration max = config.maxLockout();

      // 1 -> initial, 2 -> 2x, 3 -> 4x ... capped at max
      long shift = Math.max(0, level - 1);
      Duration scaled;
      try {
        scaled = initial.multipliedBy(1L << Math.min(shift, 30));
      } catch (ArithmeticException overflow) {
        scaled = max;
      }
      return scaled.compareTo(max) > 0 ? max : scaled;
    }
  }
}
