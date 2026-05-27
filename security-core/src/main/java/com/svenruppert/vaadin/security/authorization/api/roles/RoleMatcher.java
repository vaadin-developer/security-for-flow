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

import java.util.Collection;

/**
 * Generic role matching helper.
 */
public final class RoleMatcher {

  private RoleMatcher() {
  }

  /**
   * Checks whether any required role is present in the granted set.
   * Direct membership check — does not consult any
   * {@link RoleHierarchy}. Use
   * {@link #containsAnyImplied(Collection, Collection, RoleHierarchy)}
   * to honour role inheritance.
   *
   * @param granted  granted roles
   * @param required required roles
   * @return true if at least one required role is granted directly
   */
  public static boolean containsAny(Collection<RoleName> granted, Collection<RoleName> required) {
    return required.stream().anyMatch(granted::contains);
  }

  /**
   * Checks whether any required role is satisfied by the granted set
   * under the given {@link RoleHierarchy}. A held role matches a
   * required role if {@code hierarchy.impliesRole(held, required)}
   * returns {@code true} — which is true for the
   * {@link NoopRoleHierarchy} exactly when {@code held.equals(required)}.
   *
   * @param granted   granted roles
   * @param required  required roles
   * @param hierarchy role hierarchy; must not be {@code null}
   * @return true if at least one held role satisfies one required role
   */
  public static boolean containsAnyImplied(
      Collection<RoleName> granted,
      Collection<RoleName> required,
      RoleHierarchy hierarchy) {
    if (hierarchy == null) {
      throw new NullPointerException("hierarchy must not be null");
    }
    if (granted.isEmpty() || required.isEmpty()) {
      return false;
    }
    for (RoleName held : granted) {
      java.util.Set<RoleName> implied = hierarchy.impliedRoles(held);
      for (RoleName req : required) {
        if (implied.contains(req)) {
          return true;
        }
      }
    }
    return false;
  }
}
