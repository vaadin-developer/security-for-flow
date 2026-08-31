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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Reduced security identity used for access decisions.
 * <p>
 * This record intentionally contains no credentials, password hashes, tokens,
 * secrets, or full domain user state.
 *
 * @param subjectId   stable unique subject id in the consuming application
 * @param displayName display name only
 * @param roles       assigned roles
 * @param permissions assigned permissions
 */
public record JSentinelSubject(
    String subjectId,
    String displayName,
    Set<RoleName> roles,
    Set<PermissionName> permissions
) implements HasRoles, HasPermissions {

  /**
   * Creates a security subject with defensive copies.
   *
   * @param subjectId   stable unique subject id in the consuming application
   * @param displayName display name only
   * @param roles       assigned roles
   * @param permissions assigned permissions
   */
  public JSentinelSubject {
    if (subjectId == null || subjectId.isBlank()) {
      throw new IllegalArgumentException("Subject id must not be blank");
    }
    displayName = requireNonNull(displayName, "displayName must not be null");
    roles = Set.copyOf(requireNonNull(roles, "roles must not be null"));
    permissions = Set.copyOf(requireNonNull(permissions, "permissions must not be null"));
  }

  @Override
  public Set<RoleName> roleNames() {
    return roles;
  }

  @Override
  public Set<PermissionName> permissionNames() {
    return permissions;
  }
}
