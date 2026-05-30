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
package com.svenruppert.vaadin.security.session;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link SecurityVersionStore} backed by a
 * {@link ConcurrentHashMap}. Atomic increments through
 * {@link ConcurrentHashMap#compute(Object, java.util.function.BiFunction)}.
 */
@ExperimentalSecurityApi
public final class InMemorySecurityVersionStore implements SecurityVersionStore {

  private final ConcurrentHashMap<SecurityVersionKey, SecurityVersion> versions =
      new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemorySecurityVersionStore() {
  }

  @Override
  public SecurityVersion current(SecurityVersionKey key) {
    requireNonNull(key, "key must not be null");
    SecurityVersion v = versions.get(key);
    return v == null ? SecurityVersion.INITIAL : v;
  }

  @Override
  public SecurityVersion increment(SecurityVersionKey key) {
    requireNonNull(key, "key must not be null");
    return versions.compute(key, (k, prev) ->
        prev == null ? SecurityVersion.INITIAL.next() : prev.next());
  }

  @Override
  public void reset(SecurityVersionKey key) {
    requireNonNull(key, "key must not be null");
    versions.remove(key);
  }
}
