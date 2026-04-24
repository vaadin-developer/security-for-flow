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

import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.impl.Access;
import com.vaadin.flow.router.Location;

import java.lang.annotation.Annotation;
import java.util.Set;

import static com.svenruppert.vaadin.security.authorization.impl.Access.granted;
import static com.svenruppert.vaadin.security.authorization.impl.Access.restricted;

@ExperimentalSecurityApi("Permission-based access evaluation is experimental. Use role-based access for stable production use.")
public abstract class PermissionBasedAccessEvaluator<T extends Annotation, U>
    implements AccessEvaluator<T> {

  public abstract AuthorizationService<U> authorizationService();

  public abstract U activeSubject();

  public abstract Set<PermissionName> requiredPermissions(T annotation);

  /**
   * based on the situation a alternative navigation target could be
   * defined. This method will be called if the original navigation target could not
   * be ued based on missing Roles/Permissions of the active user.
   *
   * @param location actual position
   * @param navigationTarget next target to go
   * @param annotation that holds the static info
   * @return granted Access or a restricted one with an alternative navigation target
   */
  public abstract String alternativeNavigationTarget(Location location, Class<?> navigationTarget, T annotation);

  @Override
  public Access evaluate(Location location, Class<?> navigationTarget, T annotation) {
    final Set<PermissionName> permissions = requiredPermissions(annotation);

    //TODO implicit assumption that there will be only one active Role!
    return authorizationService().permissionsFor(activeSubject())
                                 .permissionNames()
                                 .stream()
                                 .filter(permissions::contains)
                                 .findFirst()
                                 .map(rn -> granted())
                                 .orElse(restricted(alternativeNavigationTarget(location, navigationTarget, annotation),
                                                    true));
  }


}
