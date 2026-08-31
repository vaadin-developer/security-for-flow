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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Wrapper for a permission name string.
 *
 * @param permissionName the permission identifier
 */
@ExperimentalJCustosApi("Permission-based access is experimental. Use role-based access for stable production use.")
public record PermissionName(String permissionName) {

  /**
   * Creates a permission name.
   *
   * @param permissionName the permission identifier
   */
  public PermissionName {
    if (permissionName == null || permissionName.isBlank()) {
      throw new IllegalArgumentException("Permission name must not be blank");
    }
  }

  /**
   * Alias for generic code that treats names as values.
   *
   * @return the permission identifier
   */
  public String value() {
    return permissionName;
  }
}
