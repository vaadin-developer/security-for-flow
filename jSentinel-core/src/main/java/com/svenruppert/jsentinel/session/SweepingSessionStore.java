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
package com.svenruppert.jsentinel.session;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.SessionExpired;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Lifetime-aware {@link SessionStore} decorator (V00.81) — closes the gap
 * that session records never left {@link SessionStatus#ACTIVE}: expiry was
 * only evaluated lazily on the session's own activity, so a session whose
 * browser simply went away stayed {@code ACTIVE} in the store forever, and
 * the retention promise of the {@link SessionStore} JavaDoc had no
 * implementation.
 *
 * <p>Every read path sweeps the records it returns, without a background
 * thread:
 *
 * <ul>
 *   <li>an {@link SessionStatus#ACTIVE} record whose
 *       {@link SessionPolicy#evaluate(SessionMetadata)} decision is
 *       {@link SessionPolicyDecision.IdleTimeout} or
 *       {@link SessionPolicyDecision.AbsoluteLifetimeExceeded} is persisted
 *       as {@link SessionStatus#EXPIRED} and a single
 *       {@link SessionExpired} audit event is emitted (never-throwing,
 *       mirroring {@code TimeoutSessionPolicy});</li>
 *   <li>a terminal record ({@code EXPIRED} / {@code REVOKED}) whose
 *       {@link SessionRecord#lastActivityAt()} lies further back than the
 *       retention window is deleted and dropped from the result — the
 *       {@code lastActivityAt} of a terminal record no longer advances, so
 *       it anchors the retention clock.</li>
 * </ul>
 *
 * <p>Wrap the concrete store once at wiring time:
 * {@code new SweepingSessionStore(new InMemorySessionStore(), policy)} —
 * admin views calling {@link #findAll()} (e.g. {@code SessionManagementView})
 * then always see the policy-true lifecycle state.
 *
 * @since 00.81.00
 */
@ExperimentalJSentinelApi
public final class SweepingSessionStore implements SessionStore {

  /** Audit reason emitted for an idle-timeout sweep — mirrors {@code TimeoutSessionPolicy}. */
  static final String REASON_IDLE_TIMEOUT = "IdleTimeout";
  /** Audit reason emitted for an absolute-lifetime sweep — mirrors {@code TimeoutSessionPolicy}. */
  static final String REASON_ABSOLUTE_LIFETIME = "AbsoluteLifetimeExceeded";

  /** Default retention for terminal records: 30 days. */
  public static final Duration DEFAULT_TERMINAL_RETENTION = Duration.ofDays(30);

  private final SessionStore delegate;
  private final SessionPolicy<?> policy;
  private final Duration terminalRetention;
  private final Clock clock;
  private final JSentinelAuditService auditService;

  /**
   * Decorates {@code delegate} with the {@link #DEFAULT_TERMINAL_RETENTION},
   * the system UTC clock and resolver-provided audit.
   *
   * @param delegate the concrete store; must not be {@code null}
   * @param policy   the lifetime policy consulted per record; must not be {@code null}
   */
  public SweepingSessionStore(SessionStore delegate, SessionPolicy<?> policy) {
    this(delegate, policy, DEFAULT_TERMINAL_RETENTION, Clock.systemUTC(), null);
  }

  /**
   * @param delegate          the concrete store; must not be {@code null}
   * @param policy            the lifetime policy consulted per record; must not be {@code null}
   * @param terminalRetention how long a terminal (EXPIRED/REVOKED) record is
   *                          kept for audit queries before the sweep deletes
   *                          it; must be positive
   * @param clock             time source — fixed clocks make testing deterministic
   * @param auditService      audit sink, or {@code null} to resolve from
   *                          {@link JSentinelServiceResolver} on each event
   */
  public SweepingSessionStore(SessionStore delegate, SessionPolicy<?> policy,
                              Duration terminalRetention, Clock clock,
                              JSentinelAuditService auditService) {
    this.delegate = Objects.requireNonNull(delegate, "delegate");
    this.policy = Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(terminalRetention, "terminalRetention");
    if (terminalRetention.isNegative() || terminalRetention.isZero()) {
      throw new IllegalArgumentException("terminalRetention must be positive");
    }
    this.terminalRetention = terminalRetention;
    this.clock = Objects.requireNonNull(clock, "clock");
    this.auditService = auditService;
  }

  @Override
  public void save(SessionRecord session) {
    delegate.save(session);
  }

  @Override
  public Optional<SessionRecord> findById(SessionId sessionId) {
    return delegate.findById(sessionId).flatMap(this::sweep);
  }

  @Override
  public List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId) {
    return sweepAll(delegate.findBySubject(tenant, subjectId));
  }

  @Override
  public boolean delete(SessionId sessionId) {
    return delegate.delete(sessionId);
  }

  @Override
  public List<SessionRecord> findAll() {
    return sweepAll(delegate.findAll());
  }

  private List<SessionRecord> sweepAll(List<SessionRecord> records) {
    List<SessionRecord> live = new ArrayList<>(records.size());
    for (SessionRecord record : records) {
      sweep(record).ifPresent(live::add);
    }
    return List.copyOf(live);
  }

  /**
   * Sweeps one record: expires a stale ACTIVE record (persisted + audited),
   * purges a terminal record past retention (empty result).
   */
  private Optional<SessionRecord> sweep(SessionRecord record) {
    Instant now = Instant.now(clock);
    if (record.status() == SessionStatus.ACTIVE) {
      SessionPolicyDecision decision = policy.evaluate(new SessionMetadata(
          record.subjectId().value(), record.createdAt(), record.lastActivityAt()));
      if (decision instanceof SessionPolicyDecision.Active) {
        return Optional.of(record);
      }
      SessionRecord expired = record.withStatus(SessionStatus.EXPIRED);
      delegate.save(expired);
      publish(new SessionExpired(now, record.subjectId().value(),
          record.sessionId().value(), reasonFor(decision)));
      return Optional.of(expired);
    }
    // terminal record — purge once the retention window has passed; the
    // lastActivityAt of a terminal record no longer advances.
    if (now.isAfter(record.lastActivityAt().plus(terminalRetention))) {
      delegate.delete(record.sessionId());
      return Optional.empty();
    }
    return Optional.of(record);
  }

  private static String reasonFor(SessionPolicyDecision decision) {
    return decision instanceof SessionPolicyDecision.AbsoluteLifetimeExceeded
        ? REASON_ABSOLUTE_LIFETIME
        : REASON_IDLE_TIMEOUT;
  }

  private void publish(AuditEvent event) {
    JSentinelAuditService sink = auditService != null
        ? auditService
        : JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never let a sweep fail because the audit sink failed
    }
  }
}
