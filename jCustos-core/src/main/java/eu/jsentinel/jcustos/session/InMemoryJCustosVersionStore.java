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

import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link JCustosVersionStore} backed by a
 * {@link ConcurrentHashMap}. Atomic increments through
 * {@link ConcurrentHashMap#compute(Object, java.util.function.BiFunction)}.
 */
@ExperimentalJCustosApi
public final class InMemoryJCustosVersionStore implements JCustosVersionStore {

  private final ConcurrentHashMap<JCustosVersionKey, JCustosVersion> versions =
      new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryJCustosVersionStore() {
  }

  @Override
  public JCustosVersion current(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    JCustosVersion v = versions.get(key);
    return v == null ? JCustosVersion.INITIAL : v;
  }

  @Override
  public JCustosVersion increment(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    return versions.compute(key, (k, prev) ->
        prev == null ? JCustosVersion.INITIAL.next() : prev.next());
  }

  @Override
  public void reset(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    versions.remove(key);
  }
}
