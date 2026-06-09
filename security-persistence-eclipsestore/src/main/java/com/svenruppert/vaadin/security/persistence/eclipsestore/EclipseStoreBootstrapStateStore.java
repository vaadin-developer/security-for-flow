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

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.bootstrap.BootstrapState;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStateStore;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link BootstrapStateStore}. */
final class EclipseStoreBootstrapStateStore implements BootstrapStateStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreBootstrapStateStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<BootstrapState> find(TenantId tenant) {
    requireNonNull(tenant, "tenant must not be null");
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().bootstrapStates.get(tenant));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void save(BootstrapState state) {
    requireNonNull(state, "state must not be null");
    storage.lock().writeLock().lock();
    try {
      storage.root().bootstrapStates.put(state.tenant(), state);
      storage.manager().store(storage.root().bootstrapStates);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean delete(TenantId tenant) {
    requireNonNull(tenant, "tenant must not be null");
    storage.lock().writeLock().lock();
    try {
      boolean removed = storage.root().bootstrapStates.remove(tenant) != null;
      if (removed) {
        storage.manager().store(storage.root().bootstrapStates);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
