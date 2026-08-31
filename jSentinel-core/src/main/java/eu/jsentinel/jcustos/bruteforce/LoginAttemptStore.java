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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistent counter store for the {@link LoginAttemptPolicy} family.
 * <p>
 * The existing default {@code InMemoryLoginAttemptPolicy} keeps its
 * counters in process memory — fine for a single-instance demo, but
 * unsuited for clustered deployments or for tracking lockouts across
 * restarts. A store-backed policy (planned for Phase 4) delegates
 * counter mutation and lookup to a {@code LoginAttemptStore}, so the
 * lockout state survives the process and is shared across nodes.
 *
 * <p>The API is behaviour-flavoured rather than pure CRUD because
 * the data shape is so narrow (counter + timestamp): callers either
 * record an additional failure, ask how many failures the key has
 * accumulated, or reset it on a successful login.
 *
 * <p>Implementations must be thread-safe; concurrent
 * {@code recordFailure} calls happen on every failed login.
 */
@ExperimentalJSentinelApi
public interface LoginAttemptStore {

  /**
   * Increments the failure counter for {@code key} by one and updates
   * its last-failure instant to {@code at}.
   *
   * @param key failure dimension; must not be {@code null}
   * @param at  instant the failure occurred; must not be {@code null}
   */
  void recordFailure(LoginAttemptKey key, Instant at);

  /**
   * Returns the number of failures currently held against {@code key}.
   * Zero when the key has never failed or has been {@link #reset(LoginAttemptKey)}.
   *
   * @param key failure dimension; must not be {@code null}
   * @return non-negative failure count
   */
  int failureCount(LoginAttemptKey key);

  /**
   * Returns the timestamp of the most recent failure on {@code key},
   * if any.
   *
   * @param key failure dimension; must not be {@code null}
   * @return last failure instant, or empty when never failed
   */
  Optional<Instant> lastFailureAt(LoginAttemptKey key);

  /**
   * Clears any state associated with {@code key} — used after a
   * successful login to start the counter from zero again.
   *
   * @param key failure dimension; must not be {@code null}
   */
  void reset(LoginAttemptKey key);
}
