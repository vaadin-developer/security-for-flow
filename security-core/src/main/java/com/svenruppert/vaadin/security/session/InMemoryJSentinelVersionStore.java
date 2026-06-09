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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;

import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link JSentinelVersionStore} backed by a
 * {@link ConcurrentHashMap}. Atomic increments through
 * {@link ConcurrentHashMap#compute(Object, java.util.function.BiFunction)}.
 */
@ExperimentalJSentinelApi
public final class InMemoryJSentinelVersionStore implements JSentinelVersionStore {

  private final ConcurrentHashMap<JSentinelVersionKey, JSentinelVersion> versions =
      new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryJSentinelVersionStore() {
  }

  @Override
  public JSentinelVersion current(JSentinelVersionKey key) {
    requireNonNull(key, "key must not be null");
    JSentinelVersion v = versions.get(key);
    return v == null ? JSentinelVersion.INITIAL : v;
  }

  @Override
  public JSentinelVersion increment(JSentinelVersionKey key) {
    requireNonNull(key, "key must not be null");
    return versions.compute(key, (k, prev) ->
        prev == null ? JSentinelVersion.INITIAL.next() : prev.next());
  }

  @Override
  public void reset(JSentinelVersionKey key) {
    requireNonNull(key, "key must not be null");
    versions.remove(key);
  }
}
