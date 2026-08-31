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
package eu.jsentinel.jcustos.authorization.api.permissions;

import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Merges role-to-permission lookups for a set of roles.
 * <p>
 * Two flavours:
 * <ul>
 *   <li>{@link #permissionsForRoles(Set, RolePermissionMapping)} — flat
 *       resolution: every supplied role is looked up directly in the
 *       mapping, results are unioned. No inheritance.</li>
 *   <li>{@link #permissionsForRoles(Set, RolePermissionMapping,
 *       RoleHierarchy)} — hierarchy-aware: every supplied role is first
 *       expanded through {@link RoleHierarchy#impliedRoles(RoleName)},
 *       then each implied role is looked up in the mapping. Combines
 *       role inheritance with the role-to-permission mapping into a
 *       single transitive permission set.</li>
 * </ul>
 *
 * <p>Both flavours are pure and side-effect-free; the returned set is
 * immutable.
 */
public final class RolePermissionResolver {

  private RolePermissionResolver() {
  }

  /**
   * Resolves the union of permissions associated with the supplied
   * roles, without consulting any {@link RoleHierarchy}.
   *
   * @param roles   roles held by the subject; must not be {@code null}
   * @param mapping role-to-permission lookup; must not be {@code null}
   * @return immutable union of every permission the mapping returns for
   *         any of the supplied roles; empty when {@code roles} is empty
   *         or none of them have permissions assigned
   * @throws NullPointerException if either argument is {@code null}
   */
  public static Set<PermissionName> permissionsForRoles(
      Set<RoleName> roles,
      RolePermissionMapping mapping) {
    Objects.requireNonNull(roles, "roles");
    Objects.requireNonNull(mapping, "mapping");
    Set<PermissionName> result = new LinkedHashSet<>();
    for (RoleName role : roles) {
      result.addAll(mapping.permissionsFor(role));
    }
    return Set.copyOf(result);
  }

  /**
   * Resolves the union of permissions associated with the supplied
   * roles <strong>and every role they imply via the supplied
   * hierarchy</strong>.
   *
   * <p>For each role in {@code roles}, the method first computes
   * {@code hierarchy.impliedRoles(role)} — which always contains the
   * role itself — and then looks up every member of that closure in
   * {@code mapping}. The result unions all returned permission sets.
   *
   * <p>Composing role inheritance with a role-to-permission mapping is
   * the usual deployment shape: applications declare permissions
   * narrowly (one role &rarr; the permissions it directly grants) and
   * keep transitive promotion ("ADMIN inherits EDITOR") inside the
   * hierarchy, rather than duplicating permission listings.
   *
   * @param roles     roles held by the subject; must not be {@code null}
   * @param mapping   role-to-permission lookup; must not be {@code null}
   * @param hierarchy role-inheritance graph; must not be {@code null}
   *                  (pass a no-op implementation to skip expansion)
   * @return immutable union of every permission the mapping returns for
   *         any role in the transitive closure of {@code roles}
   * @throws NullPointerException if any argument is {@code null}
   */
  public static Set<PermissionName> permissionsForRoles(
      Set<RoleName> roles,
      RolePermissionMapping mapping,
      RoleHierarchy hierarchy) {
    Objects.requireNonNull(roles, "roles");
    Objects.requireNonNull(mapping, "mapping");
    Objects.requireNonNull(hierarchy, "hierarchy");
    Set<RoleName> expanded = new LinkedHashSet<>();
    for (RoleName role : roles) {
      expanded.addAll(hierarchy.impliedRoles(role));
    }
    return permissionsForRoles(expanded, mapping);
  }
}
