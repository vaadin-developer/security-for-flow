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

/**
 * Pluggable session policy.
 * <p>
 * The expected call sequence inside a Vaadin or REST adapter:
 * <ol>
 *   <li>{@link #onLogin(SessionContext)} — after a successful login.
 *       Implementations may emit {@code SESSION_CREATED} audit events
 *       and signal "rotate session id now" via the return value.</li>
 *   <li>{@link #beforeNavigation(SessionContext)} — before each
 *       protected navigation (Vaadin: every {@code BeforeEnterEvent} on
 *       a restricted target; REST: every authenticated request). The
 *       returned {@link SessionDecision} drives whether the navigation
 *       continues, requires re-authentication, or invalidates the
 *       session.</li>
 *   <li>{@link #onLogout(SessionContext)} — when the subject explicitly
 *       logs out. Implementations may emit {@code SESSION_INVALIDATED}
 *       audit events.</li>
 * </ol>
 *
 * <p>The default implementation {@link NoopSessionPolicy} returns
 * {@link SessionDecision.Continue#INSTANCE} for every event. The provided
 * {@link TimeoutSessionPolicy} adds idle / absolute timeouts and
 * optional session-id rotation.
 *
 * @param <U> the application's subject type
 */
public interface SessionPolicy<U> {

  /**
   * Called after a successful login.
   * <p>
   * The default returns {@link SessionDecision.Continue#INSTANCE}. Implementations
   * that want to rotate the session id after login should return
   * {@link SessionDecision.Invalidate} with a target route — the adapter
   * then closes the old session and the next request creates a fresh one.
   *
   * @param context session view at the moment of login
   * @return decision for the post-login navigation
   */
  default SessionDecision onLogin(SessionContext<U> context) {
    return SessionDecision.Continue.INSTANCE;
  }

  /**
   * Called before each protected navigation. The implementation typically
   * checks idle and absolute timeouts here and returns
   * {@link SessionDecision.RequireLogin} or
   * {@link SessionDecision.Invalidate} when a threshold has been exceeded.
   *
   * @param context current session view
   * @return decision for the navigation
   */
  SessionDecision beforeNavigation(SessionContext<U> context);

  /**
   * Called when the subject explicitly logs out.
   * <p>
   * The default is a no-op; implementations that emit audit events for
   * logout should override or delegate.
   *
   * @param context session view at the moment of logout
   */
  default void onLogout(SessionContext<U> context) {
    // intentionally empty
  }

  /**
   * Pure-query lifetime check used by the Vaadin {@code SessionLifetimeListener}
   * and the REST authentication / authorization filters.
   * <p>
   * Distinct from {@link #beforeNavigation(SessionContext)} in two ways:
   * <ul>
   *   <li>Input is the minimal {@link SessionMetadata} record — {@code subjectId},
   *       {@code createdAt}, {@code lastActivityAt}. No subject reference, no
   *       attribute bag, no client address.</li>
   *   <li>Output is the minimal {@link SessionPolicyDecision} sealed type
   *       — {@link SessionPolicyDecision.Active Active},
   *       {@link SessionPolicyDecision.IdleTimeout IdleTimeout}, or
   *       {@link SessionPolicyDecision.AbsoluteLifetimeExceeded AbsoluteLifetimeExceeded}.
   *       The adapter decides what to do with each (Vaadin reroute, REST 401,
   *       …).</li>
   * </ul>
   *
   * <p>The default returns {@link SessionPolicyDecision#active()} so policies
   * that only care about the lifecycle hooks remain valid. Implementations
   * with timeout logic — {@code TimeoutSessionPolicy} — override this method.
   *
   * @param metadata current session view
   * @return decision; never {@code null}
   */
  default SessionPolicyDecision evaluate(SessionMetadata metadata) {
    return SessionPolicyDecision.active();
  }
}
