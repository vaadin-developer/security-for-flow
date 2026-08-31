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

/**
 * Extension of {@link AuthorizationService} that requires permission
 * support.
 * <p>
 * This interface exists to make the permission requirement explicit.
 * Implementations that provide both roles and permissions should
 * implement this interface. The base {@link AuthorizationService}
 * interface has a default no-op implementation of
 * {@code permissionsFor()}, so role-only implementations do not need
 * to deal with permissions at all.
 *
 * @param <U> the user/subject type
 */
@ExperimentalJSentinelApi("Permission-based authorization is experimental. "
    + "Use role-based AuthorizationService for stable production use.")
public interface PermissionAuthorizationService<U> extends AuthorizationService<U> {

  /**
   * Returns the permissions assigned to the given subject.
   * <p>
   * Unlike the default in {@link AuthorizationService}, implementations
   * of this interface must provide a real permission mapping.
   *
   * @param subject the authenticated user
   * @return the permissions for this subject
   */
  @Override
  HasPermissions permissionsFor(U subject);
}
