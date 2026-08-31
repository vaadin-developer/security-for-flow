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
package eu.jsentinel.jcustos.standalone;

import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Drives the login lifecycle for standalone applications without any
 * UI-toolkit assumption. A typical CLI / desktop main loop calls
 * {@link #login(Object, String)} once with the user-entered credentials
 * and the displayed username (used for brute-force tracking + audit),
 * then carries on with the request-handling loop.
 * <p>
 * Behaviour mirrors the Vaadin / REST flow:
 * <ol>
 *   <li>Ask {@link LoginAttemptPolicy} whether the username is currently
 *       throttled — return {@link LoginResult#lockedOut} on a hit so the
 *       caller can render a wait time.</li>
 *   <li>Delegate to the registered {@link AuthenticationService}.</li>
 *   <li>On success — load the subject, bind it into the active
 *       {@link eu.jsentinel.jcustos.authorization.api.SubjectStore},
 *       record the success on the policy and emit a
 *       {@link LoginSucceeded} audit event.</li>
 *   <li>On failure — record the failure on the policy and emit a
 *       {@link LoginFailed} audit event.</li>
 * </ol>
 *
 * @param <T> the credentials type
 * @param <U> the subject type
 */
public final class StandaloneLoginFlow<T, U> {

  private final AuthenticationService<T, U> authenticationService;
  private final Clock clock;

  /**
   * Uses the SPI-resolved {@link AuthenticationService} and the system
   * UTC clock. The most common entry point.
   */
  public StandaloneLoginFlow() {
    this(JCustosServiceResolver.authenticationService(), Clock.systemUTC());
  }

  /**
   * Test seam. Pass an explicit {@link AuthenticationService} and clock
   * so tests can avoid SPI registration churn.
   */
  public StandaloneLoginFlow(AuthenticationService<T, U> authenticationService, Clock clock) {
    this.authenticationService = Objects.requireNonNull(authenticationService, "authenticationService");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Runs one login attempt.
   *
   * @param credentials credentials accepted by the configured
   *                    {@link AuthenticationService}
   * @param username    displayed username, used for brute-force tracking
   *                    and audit; may be {@code null} or empty for
   *                    anonymous flows (no throttling applies)
   * @return the outcome
   */
  public LoginResult<U> login(T credentials, String username) {
    LoginAttemptPolicy policy = JCustosServiceResolver.loginAttemptPolicy();
    LoginAttemptContext attempt = LoginAttemptContext.now(username, null, null);

    LoginAttemptDecision gate = policy.beforeAttempt(attempt);
    if (gate instanceof LoginAttemptDecision.LockedOut lockout) {
      return LoginResult.lockedOut(lockout);
    }

    boolean ok = authenticationService.checkCredentials(credentials);
    if (!ok) {
      policy.recordFailure(attempt);
      audit(new LoginFailed(now(), username, null, "Credentials rejected"));
      return LoginResult.rejected();
    }

    U subject = authenticationService.loadSubject(credentials);
    if (subject == null) {
      policy.recordFailure(attempt);
      audit(new LoginFailed(now(), username, null, "Subject lookup returned null"));
      return LoginResult.rejected();
    }

    SubjectStores.subjectStore().setCurrentSubject(subject, authenticationService.subjectType());
    policy.recordSuccess(attempt);
    audit(new LoginSucceeded(now(), username, null, null));
    return LoginResult.success(subject);
  }

  /**
   * Removes the current subject from the {@link eu.jsentinel.jcustos.authorization.api.SubjectStore}.
   * Does not emit an audit event — that is the {@code LogoutService}'s
   * responsibility, which standalone applications wire up explicitly
   * when they need it.
   */
  public void logout() {
    SubjectStores.subjectStore().deleteCurrentSubject(authenticationService.subjectType());
    // V00.74: clear the propagation slot so a subsequent thread (or a
    // re-login in the same thread) starts without a stale credential.
    // Best-effort: the SPI store may not be registered in setups that
    // do not opt into V00.74 propagation.
    JCustosServiceResolver.findTokenCredentialStore()
        .ifPresent(eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore::clear);
  }

  /**
   * V00.74 — bind a {@link TokenCredential} for the current thread so
   * {@code @PropagateToken}-annotated wrappers can forward it to
   * downstream HTTP calls. Convenience for the standalone / CLI demo
   * pattern (after a successful login, the caller has the token at
   * hand and binds it here).
   *
   * <p>Looks up the SPI-resolved
   * {@code TokenCredentialStore} (see Konzept §6.3).
   *
   * @param credential the credential to bind; non-null
   */
  public void bindToken(TokenCredential credential) {
    JCustosServiceResolver.tokenCredentialStore().bind(credential);
  }

  private Instant now() {
    return Instant.now(clock);
  }

  private static void audit(eu.jsentinel.jcustos.audit.AuditEvent event) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // never block login because the audit sink failed
    }
  }

  /**
   * Outcome of a single {@link #login} call.
   *
   * @param <U> subject type
   */
  public sealed interface LoginResult<U>
      permits LoginResult.Success, LoginResult.Rejected, LoginResult.LockedOut {

    /** Credentials were valid and a subject was bound into the store. */
    record Success<U>(U subject) implements LoginResult<U> { }

    /** Credentials were invalid (wrong password, unknown user, etc.). */
    record Rejected<U>() implements LoginResult<U> { }

    /** The username is currently locked out. The caller should not retry yet. */
    record LockedOut<U>(LoginAttemptDecision.LockedOut decision) implements LoginResult<U> { }

    static <U> LoginResult<U> success(U subject) {
      return new Success<>(subject);
    }

    static <U> LoginResult<U> rejected() {
      return new Rejected<>();
    }

    static <U> LoginResult<U> lockedOut(LoginAttemptDecision.LockedOut decision) {
      return new LockedOut<>(decision);
    }
  }
}
