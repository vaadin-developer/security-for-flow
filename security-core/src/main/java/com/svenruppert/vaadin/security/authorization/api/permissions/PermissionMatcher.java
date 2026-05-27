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
package com.svenruppert.vaadin.security.authorization.api.permissions;

import java.util.Collection;

/**
 * Generic permission matching helper.
 * <p>
 * Supports exact matches and a generic terminal wildcard such as
 * {@code resource:*}. It contains no project-specific permission names.
 */
public final class PermissionMatcher {

  private PermissionMatcher() {
  }

  /**
   * Checks whether the granted permission matches the required permission.
   *
   * @param granted  granted permission
   * @param required required permission
   * @return true if matched
   */
  public static boolean matches(PermissionName granted, PermissionName required) {
    String grantedValue = granted.value();
    String requiredValue = required.value();
    if (grantedValue.equals(requiredValue)) {
      return true;
    }
    if (grantedValue.endsWith(":*")) {
      String prefix = grantedValue.substring(0, grantedValue.length() - 1);
      return requiredValue.startsWith(prefix);
    }
    return false;
  }

  /**
   * Checks whether all required permissions are covered by the granted set.
   *
   * @param granted  granted permissions
   * @param required required permissions
   * @return true if all required permissions match
   */
  public static boolean containsAll(
      Collection<PermissionName> granted,
      Collection<PermissionName> required) {
    return required.stream()
        .allMatch(requiredPermission -> granted.stream()
            .anyMatch(grantedPermission -> matches(grantedPermission, requiredPermission)));
  }

  /**
   * Checks whether at least one required permission is covered by the
   * granted set.
   *
   * @param granted  granted permissions
   * @param required required permissions
   * @return true if any required permission matches; false on an empty
   *         {@code required} collection
   */
  public static boolean containsAny(
      Collection<PermissionName> granted,
      Collection<PermissionName> required) {
    return required.stream()
        .anyMatch(requiredPermission -> granted.stream()
            .anyMatch(grantedPermission -> matches(grantedPermission, requiredPermission)));
  }
}
