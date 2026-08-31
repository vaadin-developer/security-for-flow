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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Persistent counter store for {@link JCustosVersion} per
 * {@link JCustosVersionKey}. Backs the planned
 * {@code JCustosVersionCheck} interceptor in
 * {@code security-vaadin} and {@code security-rest}: every session
 * captures the subject's version at login time
 * ({@link SessionRecord#securityVersionAtLogin()}); the interceptor
 * compares that snapshot against the subject's <em>current</em>
 * version returned by {@link #current(JCustosVersionKey)} on every
 * request and rejects the session when the two have drifted apart.
 *
 * <p>The API is behaviour-flavoured rather than pure CRUD because
 * the data shape is so narrow (a single non-negative counter):
 * callers either read the current version, atomically bump it, or
 * reset it. The reset path is intentional — an admin tooling that
 * forces a clean state for a tenant can call {@link #reset} per
 * subject.
 *
 * <p>Implementations must be thread-safe; concurrent {@code current}
 * and {@code increment} calls happen on every authority change.
 */
@ExperimentalJCustosApi
public interface JCustosVersionStore {

  /**
   * Returns the current {@link JCustosVersion} associated with
   * {@code key}. Returns {@link JCustosVersion#INITIAL} when the
   * key has never been incremented (i.e. the subject is fresh).
   *
   * @param key tenant + subject; must not be {@code null}
   * @return current version, never {@code null}
   */
  JCustosVersion current(JCustosVersionKey key);

  /**
   * Atomically bumps the version for {@code key} by one and returns
   * the new value. The very first call on a key transitions
   * {@link JCustosVersion#INITIAL} to value {@code 1}.
   *
   * @param key tenant + subject; must not be {@code null}
   * @return the new (post-increment) version
   */
  JCustosVersion increment(JCustosVersionKey key);

  /**
   * Resets the version for {@code key} to
   * {@link JCustosVersion#INITIAL}. No-op when no value was ever
   * recorded.
   *
   * @param key tenant + subject; must not be {@code null}
   */
  void reset(JCustosVersionKey key);
}
