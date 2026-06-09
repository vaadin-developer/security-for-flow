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
package com.svenruppert.jsentinel.ratelimiting;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Pluggable rate-limiting decision point — separate from
 * {@link com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy
 * LoginAttemptPolicy} (which is purpose-built for password-guessing
 * detection) and from
 * {@link com.svenruppert.jsentinel.session.SessionPolicy
 * SessionPolicy} (which is about session lifetime).
 * <p>
 * Callers wrap the protected operation:
 * <pre>{@code
 *   RateLimitDecision d = policy.tryAcquire(key);
 *   if (d instanceof RateLimitDecision.Throttled t) {
 *       // 429 Too Many Requests + Retry-After: t.retryAfter().toSeconds()
 *       return;
 *   }
 *   // proceed
 * }</pre>
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJSentinelApi
@FunctionalInterface
public interface RateLimitPolicy {

  /**
   * Attempts to record one event under {@code key} against the
   * policy's configured per-window limit. The default behaviour
   * mirrors a leaky bucket: an admitted event is counted, a
   * throttled event is not. Concrete implementations document
   * their semantics.
   *
   * @param key non-null key; the scope is the application's
   *            choice — IP, subject, endpoint, or composed
   * @return admit / throttle decision, never {@code null}
   */
  RateLimitDecision tryAcquire(RateLimitKey key);
}
