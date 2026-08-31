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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link JCustosVersionStore}. */
final class EclipseStoreJCustosVersionStore implements JCustosVersionStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreJCustosVersionStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public JCustosVersion current(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().readLock().lock();
    try {
      JCustosVersion v = storage.root().securityVersions.get(key);
      return v == null ? JCustosVersion.INITIAL : v;
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public JCustosVersion increment(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      JCustosVersion prev = storage.root().securityVersions.get(key);
      JCustosVersion next = prev == null
          ? JCustosVersion.INITIAL.next()
          : prev.next();
      storage.root().securityVersions.put(key, next);
      storage.manager().store(storage.root().securityVersions);
      return next;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public void reset(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      if (storage.root().securityVersions.remove(key) != null) {
        storage.manager().store(storage.root().securityVersions);
      }
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
