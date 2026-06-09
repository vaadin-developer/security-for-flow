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
import com.svenruppert.jsentinel.audit.SessionCreated;
import com.svenruppert.jsentinel.audit.SessionExpired;
import com.svenruppert.jsentinel.audit.SessionInvalidated;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Minimal {@link SessionPolicy} with idle timeout, absolute lifetime, and
 * optional session-id rotation after login.
 * <p>
 * The policy is Vaadin-free and stateless — it makes decisions purely
 * from the {@link SessionContext}'s timestamps. Tracking last-activity
 * inside the session is the adapter's job.
 *
 * <h2>Decisions</h2>
 *
 * <ul>
 *   <li>{@link #onLogin(SessionContext)} — emits
 *       {@link SessionCreated}.
 *       If {@link Config#rotateSessionAfterLogin()} is {@code true},
 *       returns {@link SessionDecision.Invalidate} so the adapter rotates
 *       the session id; otherwise {@link SessionDecision.Continue#INSTANCE}.</li>
 *   <li>{@link #beforeNavigation(SessionContext)} — checks absolute
 *       lifetime first, then idle timeout. Either trip emits
 *       {@link SessionExpired}
 *       and returns {@link SessionDecision.Invalidate}.</li>
 *   <li>{@link #onLogout(SessionContext)} — emits
 *       {@link SessionInvalidated}.</li>
 * </ul>
 *
 * @param <U> subject type
 */
public final class TimeoutSessionPolicy<U> implements SessionPolicy<U> {

  /**
   * Tunable thresholds.
   * <p>
   * When {@code rotateSessionAfterLogin} is {@code true},
   * {@link #onLogin(SessionContext)} returns
   * {@link SessionDecision.Invalidate} so the calling adapter rotates
   * the underlying session id. The Vaadin {@code LoginView} honours this
   * by calling {@code VaadinService.reinitializeSession(VaadinRequest)} —
   * the {@code VaadinSession} (and therefore the just-bound subject)
   * survives the rotation; only the HTTP session id changes. The
   * REST adapter has no equivalent — tokens themselves are the session,
   * and there is no fixation surface to mitigate.
   *
   * @param idleTimeout             maximum allowed time since the last
   *                                observed activity before the session
   *                                is treated as idle-timeout
   * @param absoluteLifetime        maximum allowed time since session
   *                                creation, regardless of activity
   * @param rotateSessionAfterLogin if {@code true}, {@code onLogin}
   *                                returns {@code Invalidate} so the
   *                                adapter rotates the HTTP session id
   * @param loginRoute              route used for the {@code Invalidate}
   *                                decision in the {@code beforeNavigation}
   *                                context (ignored after login rotation)
   */
  public record Config(
      Duration idleTimeout,
      Duration absoluteLifetime,
      boolean rotateSessionAfterLogin,
      String loginRoute
  ) {
    public Config {
      Objects.requireNonNull(idleTimeout, "idleTimeout");
      Objects.requireNonNull(absoluteLifetime, "absoluteLifetime");
      Objects.requireNonNull(loginRoute, "loginRoute");
      if (loginRoute.isBlank()) {
        throw new IllegalArgumentException("loginRoute must not be blank");
      }
      if (idleTimeout.isNegative() || idleTimeout.isZero()) {
        throw new IllegalArgumentException("idleTimeout must be positive");
      }
      if (absoluteLifetime.isNegative() || absoluteLifetime.isZero()) {
        throw new IllegalArgumentException("absoluteLifetime must be positive");
      }
    }

    /** Sensible defaults — 30 min idle, 12 h absolute, rotate after login, /login. */
    public static Config defaults() {
      return new Config(Duration.ofMinutes(30), Duration.ofHours(12), true, "/login");
    }
  }

  private final Config config;
  private final Clock clock;
  private final JSentinelAuditService auditService;

  public TimeoutSessionPolicy() {
    this(Config.defaults(), Clock.systemUTC(), null);
  }

  /**
   * @param config       thresholds and post-login behaviour
   * @param clock        time source — fixed clocks make testing deterministic
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link JSentinelServiceResolver} on each event
   */
  public TimeoutSessionPolicy(Config config, Clock clock, JSentinelAuditService auditService) {
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.auditService = auditService;
  }

  @Override
  public SessionDecision onLogin(SessionContext<U> context) {
    publish(new SessionCreated(
        Instant.now(clock), subjectIdOf(context), context.sessionId()));
    if (config.rotateSessionAfterLogin()) {
      return new SessionDecision.Invalidate("Session rotated after login", config.loginRoute());
    }
    return SessionDecision.Continue.INSTANCE;
  }

  @Override
  public SessionDecision beforeNavigation(SessionContext<U> context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);

    if (now.isAfter(context.createdAt().plus(config.absoluteLifetime()))) {
      publish(new SessionExpired(
          Instant.now(clock), subjectIdOf(context), context.sessionId(),
          "AbsoluteLifetimeExceeded"));
      return new SessionDecision.Invalidate("Session lifetime exceeded", config.loginRoute());
    }
    Instant lastActivity = context.lastActivity() == null ? context.createdAt() : context.lastActivity();
    if (now.isAfter(lastActivity.plus(config.idleTimeout()))) {
      publish(new SessionExpired(
          Instant.now(clock), subjectIdOf(context), context.sessionId(),
          "IdleTimeout"));
      return new SessionDecision.Invalidate("Session idle timeout", config.loginRoute());
    }
    return SessionDecision.Continue.INSTANCE;
  }

  /**
   * Pure-query lifetime check called by the Vaadin
   * {@code SessionLifetimeListener} and by the REST filters.
   * <p>
   * Returns {@link SessionPolicyDecision.AbsoluteLifetimeExceeded} first
   * when both bounds are tripped — the absolute lifetime trumps the
   * idle timeout, mirroring the precedence in
   * {@link #beforeNavigation(SessionContext)}.
   * <p>
   * Audit emit-sites are deliberately not duplicated here:
   * {@link #beforeNavigation(SessionContext)} is the audit boundary,
   * since the lifecycle hooks carry the richer
   * {@link SessionContext#subject() subject} and
   * {@link SessionContext#sessionId() sessionId}. The Vaadin / REST
   * adapter that calls {@code evaluate(...)} is expected to emit the
   * audit event itself when it acts on the decision.
   *
   * @param metadata current session view
   * @return decision; never {@code null}
   */
  @Override
  public SessionPolicyDecision evaluate(SessionMetadata metadata) {
    Objects.requireNonNull(metadata, "metadata");
    Instant now = Instant.now(clock);

    if (now.isAfter(metadata.createdAt().plus(config.absoluteLifetime()))) {
      return SessionPolicyDecision.absoluteLifetimeExceeded();
    }
    if (now.isAfter(metadata.lastActivityAt().plus(config.idleTimeout()))) {
      return SessionPolicyDecision.idleTimeout();
    }
    return SessionPolicyDecision.active();
  }

  @Override
  public void onLogout(SessionContext<U> context) {
    publish(new SessionInvalidated(
        Instant.now(clock), subjectIdOf(context), context.sessionId(), "Logout"));
  }

  private String subjectIdOf(SessionContext<U> context) {
    return context.subject() == null ? "" : context.subject().toString();
  }

  private void publish(AuditEvent event) {
    JSentinelAuditService sink = auditService != null
        ? auditService
        : JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block a session decision because the audit sink failed
    }
  }
}
