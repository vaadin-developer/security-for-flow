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
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;

import java.util.List;

/**
 * Maps a user subject to its authorization data.
 * <p>
 * The stable API requires only {@link #rolesFor(Object)}.
 * The permission-based method {@link #permissionsFor(Object)} has a default
 * implementation returning empty permissions, making it optional.
 * Implementations that need permission support should also implement
 * {@link PermissionAuthorizationService}.
 *
 * @param <U> the user/subject type
 * @see PermissionAuthorizationService
 */
public interface AuthorizationService<U> {

  /**
   * Returns the roles assigned to the given subject.
   *
   * @param subject the authenticated user
   * @return the roles for this subject
   */
  HasRoles rolesFor(U subject);

  /**
   * Returns the permissions assigned to the given subject.
   * <p>
   * The default implementation returns empty permissions. Override this
   * method or implement {@link PermissionAuthorizationService} to provide
   * permission-based authorization.
   *
   * @param subject the authenticated user
   * @return the permissions for this subject
   * @see PermissionAuthorizationService
   */
  @ExperimentalJCustosApi("Permission-based authorization is experimental. "
      + "Override this method or implement PermissionAuthorizationService.")
  default HasPermissions permissionsFor(U subject) {
    return List::of;
  }
}
