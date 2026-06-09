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
package com.svenruppert.jsentinel.persistence.eclipsestore;

import com.svenruppert.jsentinel.session.JSentinelVersion;
import com.svenruppert.jsentinel.session.JSentinelVersionKey;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link JSentinelVersionStore}. */
final class EclipseStoreJSentinelVersionStore implements JSentinelVersionStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreJSentinelVersionStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public JSentinelVersion current(JSentinelVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().readLock().lock();
    try {
      JSentinelVersion v = storage.root().securityVersions.get(key);
      return v == null ? JSentinelVersion.INITIAL : v;
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public JSentinelVersion increment(JSentinelVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      JSentinelVersion prev = storage.root().securityVersions.get(key);
      JSentinelVersion next = prev == null
          ? JSentinelVersion.INITIAL.next()
          : prev.next();
      storage.root().securityVersions.put(key, next);
      storage.manager().store(storage.root().securityVersions);
      return next;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public void reset(JSentinelVersionKey key) {
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
