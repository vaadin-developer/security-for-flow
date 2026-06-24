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

import com.svenruppert.jsentinel.authorization.api.roles.RoleAssignmentKey;
import com.svenruppert.jsentinel.authorization.api.roles.RoleAssignmentStore;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.LinkedHashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link RoleAssignmentStore}. */
final class EclipseStoreRoleAssignmentStore implements RoleAssignmentStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreRoleAssignmentStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public Set<RoleName> findRoles(RoleAssignmentKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().readLock().lock();
    try {
      Set<RoleName> roles = storage.root().roleAssignments.get(key);
      return roles == null ? Set.of() : Set.copyOf(roles);
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void setRoles(RoleAssignmentKey key, Set<RoleName> roles) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      if (roles == null || roles.isEmpty()) {
        storage.root().roleAssignments.remove(key);
      } else {
        storage.root().roleAssignments.put(key, new LinkedHashSet<>(roles));
      }
      storage.manager().store(storage.root().roleAssignments);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean assignRole(RoleAssignmentKey key, RoleName role) {
    requireNonNull(key, "key must not be null");
    requireNonNull(role, "role must not be null");
    storage.lock().writeLock().lock();
    try {
      LinkedHashSet<RoleName> set = storage.root().roleAssignments.get(key);
      boolean newKey = set == null;
      if (newKey) {
        set = new LinkedHashSet<>();
        storage.root().roleAssignments.put(key, set);
      }
      boolean added = set.add(role);
      if (added) {
        // store the mutated set itself — store(map) would not re-store an
        // already-persisted nested set (R002); also store the map for a new key.
        storage.manager().store(set);
        if (newKey) {
          storage.manager().store(storage.root().roleAssignments);
        }
      }
      return added;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean revokeRole(RoleAssignmentKey key, RoleName role) {
    requireNonNull(key, "key must not be null");
    requireNonNull(role, "role must not be null");
    storage.lock().writeLock().lock();
    try {
      LinkedHashSet<RoleName> set = storage.root().roleAssignments.get(key);
      if (set == null) {
        return false;
      }
      boolean removed = set.remove(role);
      if (removed) {
        if (set.isEmpty()) {
          // entry removal mutates the map itself, which store(map) persists.
          storage.root().roleAssignments.remove(key);
          storage.manager().store(storage.root().roleAssignments);
        } else {
          // persist the in-place set mutation (R002).
          storage.manager().store(set);
        }
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public void clearRoles(RoleAssignmentKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      if (storage.root().roleAssignments.remove(key) != null) {
        storage.manager().store(storage.root().roleAssignments);
      }
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
