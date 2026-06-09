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
package com.svenruppert.jsentinel.test;

import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Programmable in-memory {@link AuthorizationService} for tests.
 * <p>
 * Roles and permissions per subject are configured via
 * {@link #put(Object, Set, Set)} / {@link #putRoles(Object, Set)} /
 * {@link #putPermissions(Object, Set)}. Unknown subjects yield empty
 * roles and permissions — never throws, so policies see a graceful
 * deny instead of an exception.
 *
 * @param <U> subject type
 */
public final class FakeAuthorizationService<U> implements AuthorizationService<U> {

  private final Map<U, Set<RoleName>> roles = new HashMap<>();
  private final Map<U, Set<PermissionName>> permissions = new HashMap<>();

  /**
   * Replaces any existing roles and permissions for {@code subject}.
   *
   * @param subject       non-{@code null} subject
   * @param subjectRoles  read-only set of roles; must not be {@code null}
   * @param subjectPerms  read-only set of permissions; must not be {@code null}
   * @return this fake
   */
  public FakeAuthorizationService<U> put(
      U subject, Set<RoleName> subjectRoles, Set<PermissionName> subjectPerms) {
    requireNonNull(subject, "subject must not be null");
    roles.put(subject, Set.copyOf(requireNonNull(subjectRoles, "subjectRoles must not be null")));
    permissions.put(subject, Set.copyOf(requireNonNull(subjectPerms, "subjectPerms must not be null")));
    return this;
  }

  /**
   * Replaces only the roles for {@code subject}; existing permissions
   * stay in place.
   *
   * @param subject      non-{@code null} subject
   * @param subjectRoles new role set
   * @return this fake
   */
  public FakeAuthorizationService<U> putRoles(U subject, Set<RoleName> subjectRoles) {
    requireNonNull(subject, "subject must not be null");
    roles.put(subject, Set.copyOf(requireNonNull(subjectRoles, "subjectRoles must not be null")));
    return this;
  }

  /**
   * Replaces only the permissions for {@code subject}; existing roles
   * stay in place.
   *
   * @param subject      non-{@code null} subject
   * @param subjectPerms new permission set
   * @return this fake
   */
  public FakeAuthorizationService<U> putPermissions(U subject, Set<PermissionName> subjectPerms) {
    requireNonNull(subject, "subject must not be null");
    permissions.put(subject, Set.copyOf(requireNonNull(subjectPerms, "subjectPerms must not be null")));
    return this;
  }

  /** Clears all role and permission entries. */
  public void clear() {
    roles.clear();
    permissions.clear();
  }

  @Override
  public HasRoles rolesFor(U subject) {
    Set<RoleName> assigned = roles.getOrDefault(subject, Set.of());
    return () -> List.copyOf(assigned);
  }

  @Override
  public HasPermissions permissionsFor(U subject) {
    Set<PermissionName> assigned = permissions.getOrDefault(subject, Set.of());
    return () -> List.copyOf(assigned);
  }
}
