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
package com.svenruppert.vaadin.security.authorization.api.roles;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RoleAssignmentStore} backed by a
 * {@link ConcurrentHashMap}. Mutations are guarded with
 * {@code compute} calls so add / revoke / set don't race against
 * each other.
 */
@ExperimentalSecurityApi
public final class InMemoryRoleAssignmentStore implements RoleAssignmentStore {

  private final ConcurrentHashMap<RoleAssignmentKey, Set<RoleName>> assignments =
      new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryRoleAssignmentStore() {
  }

  @Override
  public Set<RoleName> findRoles(RoleAssignmentKey key) {
    requireNonNull(key, "key must not be null");
    Set<RoleName> roles = assignments.get(key);
    return roles == null ? Set.of() : Set.copyOf(roles);
  }

  @Override
  public void setRoles(RoleAssignmentKey key, Set<RoleName> roles) {
    requireNonNull(key, "key must not be null");
    if (roles == null || roles.isEmpty()) {
      assignments.remove(key);
    } else {
      assignments.put(key, new LinkedHashSet<>(roles));
    }
  }

  @Override
  public boolean assignRole(RoleAssignmentKey key, RoleName role) {
    requireNonNull(key, "key must not be null");
    requireNonNull(role, "role must not be null");
    boolean[] added = {false};
    assignments.compute(key, (k, prev) -> {
      LinkedHashSet<RoleName> next = prev == null
          ? new LinkedHashSet<>()
          : new LinkedHashSet<>(prev);
      added[0] = next.add(role);
      return next;
    });
    return added[0];
  }

  @Override
  public boolean revokeRole(RoleAssignmentKey key, RoleName role) {
    requireNonNull(key, "key must not be null");
    requireNonNull(role, "role must not be null");
    boolean[] removed = {false};
    assignments.computeIfPresent(key, (k, prev) -> {
      LinkedHashSet<RoleName> next = new LinkedHashSet<>(prev);
      removed[0] = next.remove(role);
      return next.isEmpty() ? null : next;
    });
    return removed[0];
  }

  @Override
  public void clearRoles(RoleAssignmentKey key) {
    requireNonNull(key, "key must not be null");
    assignments.remove(key);
  }
}
