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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Persistent counter store for {@link JSentinelVersion} per
 * {@link JSentinelVersionKey}. Backs the planned
 * {@code JSentinelVersionCheck} interceptor in
 * {@code security-vaadin} and {@code security-rest}: every session
 * captures the subject's version at login time
 * ({@link SessionRecord#securityVersionAtLogin()}); the interceptor
 * compares that snapshot against the subject's <em>current</em>
 * version returned by {@link #current(JSentinelVersionKey)} on every
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
@ExperimentalJSentinelApi
public interface JSentinelVersionStore {

  /**
   * Returns the current {@link JSentinelVersion} associated with
   * {@code key}. Returns {@link JSentinelVersion#INITIAL} when the
   * key has never been incremented (i.e. the subject is fresh).
   *
   * @param key tenant + subject; must not be {@code null}
   * @return current version, never {@code null}
   */
  JSentinelVersion current(JSentinelVersionKey key);

  /**
   * Atomically bumps the version for {@code key} by one and returns
   * the new value. The very first call on a key transitions
   * {@link JSentinelVersion#INITIAL} to value {@code 1}.
   *
   * @param key tenant + subject; must not be {@code null}
   * @return the new (post-increment) version
   */
  JSentinelVersion increment(JSentinelVersionKey key);

  /**
   * Resets the version for {@code key} to
   * {@link JSentinelVersion#INITIAL}. No-op when no value was ever
   * recorded.
   *
   * @param key tenant + subject; must not be {@code null}
   */
  void reset(JSentinelVersionKey key);
}
