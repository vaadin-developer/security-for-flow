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
package eu.jsentinel.jcustos.session;

/**
 * Outcome of {@link SessionPolicy#evaluate(SessionMetadata)}.
 * <p>
 * Sealed so callers can {@code switch} exhaustively without a default.
 * Distinct from {@link SessionDecision}, which targets the lifecycle
 * hooks ({@code onLogin} / {@code beforeNavigation} / {@code onLogout})
 * and carries adapter-facing metadata such as a target route. This
 * type is intentionally minimal — adapters translate the variant into
 * their own response (Vaadin reroute, REST 401, …).
 */
public sealed interface SessionPolicyDecision
    permits SessionPolicyDecision.Active,
            SessionPolicyDecision.IdleTimeout,
            SessionPolicyDecision.AbsoluteLifetimeExceeded {

  /** The session may continue. */
  record Active() implements SessionPolicyDecision {

    /** Shared singleton — there is only one shape of {@code Active}. */
    public static final Active INSTANCE = new Active();
  }

  /** The session was idle longer than the configured idle timeout. */
  record IdleTimeout() implements SessionPolicyDecision {

    /** Shared singleton. */
    public static final IdleTimeout INSTANCE = new IdleTimeout();
  }

  /** The session is older than the configured absolute lifetime. */
  record AbsoluteLifetimeExceeded() implements SessionPolicyDecision {

    /** Shared singleton. */
    public static final AbsoluteLifetimeExceeded INSTANCE = new AbsoluteLifetimeExceeded();
  }

  /** Convenience factory for the {@link Active} singleton. */
  static Active active() {
    return Active.INSTANCE;
  }

  /** Convenience factory for the {@link IdleTimeout} singleton. */
  static IdleTimeout idleTimeout() {
    return IdleTimeout.INSTANCE;
  }

  /** Convenience factory for the {@link AbsoluteLifetimeExceeded} singleton. */
  static AbsoluteLifetimeExceeded absoluteLifetimeExceeded() {
    return AbsoluteLifetimeExceeded.INSTANCE;
  }
}
