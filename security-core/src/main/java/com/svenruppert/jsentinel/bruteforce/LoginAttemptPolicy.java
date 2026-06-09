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

/**
 * Policy that throttles repeated failed login attempts.
 * <p>
 * The expected call sequence inside an authentication flow is:
 * <ol>
 *   <li>{@link #beforeAttempt(LoginAttemptContext)} — before the
 *       password check. If the decision is not
 *       {@link LoginAttemptDecision#allowed() allowed}, skip the
 *       check and return the user a generic "try again later" error.</li>
 *   <li>{@link #recordSuccess(LoginAttemptContext)} — after the password
 *       check succeeds. Resets the failure counter.</li>
 *   <li>{@link #recordFailure(LoginAttemptContext)} — after the password
 *       check rejects the credentials. Increments the failure counter
 *       and may escalate the throttling decision for subsequent attempts.</li>
 * </ol>
 *
 * <p>Implementations decide which key to track by — typically a
 * combination of {@code username} and {@code clientAddress}. The default
 * {@link InMemoryLoginAttemptPolicy} tracks the combined key plus the
 * raw username so an attacker cannot cycle clients to escape the
 * counter.
 */
public interface LoginAttemptPolicy {

  /**
   * Decides whether the attempt described by {@code context} may proceed.
   * Implementations <strong>must not</strong> mutate the failure counter
   * here — that is the responsibility of
   * {@link #recordSuccess(LoginAttemptContext)} /
   * {@link #recordFailure(LoginAttemptContext)} after the actual check.
   *
   * @param context attempt context
   * @return decision; never {@code null}
   */
  LoginAttemptDecision beforeAttempt(LoginAttemptContext context);

  /**
   * Records a successful attempt. Implementations typically reset the
   * per-key failure counter so a successful login lifts a partial
   * lockout immediately.
   *
   * @param context attempt context
   */
  void recordSuccess(LoginAttemptContext context);

  /**
   * Records a failed attempt. Implementations typically increment a
   * per-key counter and may escalate the throttling decision.
   *
   * @param context attempt context
   */
  void recordFailure(LoginAttemptContext context);
}
