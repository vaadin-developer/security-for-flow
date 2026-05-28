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

import java.util.Set;

/**
 * Persists the role assignments of every subject, keyed on
 * {@link RoleAssignmentKey}.
 * <p>
 * Distinct from
 * {@link com.svenruppert.vaadin.security.authorization.api.AuthorizationService}:
 * the {@code AuthorizationService} resolves the roles of a subject
 * at query time and can do so from any source (LDAP, JWT claims,
 * database). {@code RoleAssignmentStore} is the storage backend a
 * store-backed {@code AuthorizationService} implementation (planned
 * for Phase 4) can build on when the role set is genuinely owned by
 * this application.
 *
 * <p>Returned {@link Set}s are immutable; the store always returns a
 * defensive copy so callers can iterate without locking.
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalSecurityApi
public interface RoleAssignmentStore {

  /**
   * Returns the roles currently assigned to {@code key}.
   *
   * @param key tenant + subject; must not be {@code null}
   * @return immutable role set; empty when no roles are assigned
   */
  Set<RoleName> findRoles(RoleAssignmentKey key);

  /**
   * Replaces the role set for {@code key} with {@code roles}.
   *
   * @param key   tenant + subject; must not be {@code null}
   * @param roles new role set; {@code null} is treated as an empty set
   */
  void setRoles(RoleAssignmentKey key, Set<RoleName> roles);

  /**
   * Adds a single role to {@code key}'s set, if not already present.
   *
   * @param key  tenant + subject; must not be {@code null}
   * @param role role to add; must not be {@code null}
   * @return {@code true} if the role was newly added,
   *         {@code false} if it was already present
   */
  boolean assignRole(RoleAssignmentKey key, RoleName role);

  /**
   * Removes a single role from {@code key}'s set.
   *
   * @param key  tenant + subject; must not be {@code null}
   * @param role role to remove; must not be {@code null}
   * @return {@code true} if the role was present and removed,
   *         {@code false} otherwise
   */
  boolean revokeRole(RoleAssignmentKey key, RoleName role);

  /**
   * Clears every role assigned to {@code key}.
   *
   * @param key tenant + subject; must not be {@code null}
   */
  void clearRoles(RoleAssignmentKey key);
}
