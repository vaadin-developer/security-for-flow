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
package com.svenruppert.vaadin.security.persistence.eclipsestore;

import com.svenruppert.vaadin.security.session.SecurityVersion;
import com.svenruppert.vaadin.security.session.SecurityVersionKey;
import com.svenruppert.vaadin.security.session.SecurityVersionStore;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link SecurityVersionStore}. */
final class EclipseStoreSecurityVersionStore implements SecurityVersionStore {

  private final EclipseStoreSecurityStorage storage;

  EclipseStoreSecurityVersionStore(EclipseStoreSecurityStorage storage) {
    this.storage = storage;
  }

  @Override
  public SecurityVersion current(SecurityVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().readLock().lock();
    try {
      SecurityVersion v = storage.root().securityVersions.get(key);
      return v == null ? SecurityVersion.INITIAL : v;
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public SecurityVersion increment(SecurityVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      SecurityVersion prev = storage.root().securityVersions.get(key);
      SecurityVersion next = prev == null
          ? SecurityVersion.INITIAL.next()
          : prev.next();
      storage.root().securityVersions.put(key, next);
      storage.manager().store(storage.root().securityVersions);
      return next;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public void reset(SecurityVersionKey key) {
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
