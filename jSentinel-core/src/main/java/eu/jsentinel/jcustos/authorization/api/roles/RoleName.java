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
package eu.jsentinel.jcustos.authorization.api.roles;

/**
 * Wrapper for a role name string.
 *
 * @param roleName the role identifier
 */
public record RoleName(String roleName) {

  /**
   * Creates a role name.
   *
   * @param roleName the role identifier
   */
  public RoleName {
    if (roleName == null || roleName.isBlank()) {
      throw new IllegalArgumentException("Role name must not be blank");
    }
  }

  /**
   * Alias for generic code that treats names as values.
   *
   * @return the role identifier
   */
  public String value() {
    return roleName;
  }
}
