/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rapidpm.vaadin.security.authorization.api.permissions;

import com.vaadin.flow.router.Location;
import org.rapidpm.vaadin.security.authorization.api.AccessEvaluator;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationService;
import org.rapidpm.vaadin.security.authorization.impl.Access;

import java.lang.annotation.Annotation;
import java.util.Set;

import static org.rapidpm.vaadin.security.authorization.impl.Access.granted;
import static org.rapidpm.vaadin.security.authorization.impl.Access.restricted;

public abstract class PermissionBasedAccessEvaluator<T extends Annotation, U>
    implements AccessEvaluator<T> {

  public abstract AuthorizationService<U> authorizationService();

  public abstract U activeSubject();

  public abstract Set<PermissionName> requiredPermissions(T annotation);

  /**
   * based on the situation a alternative navigation target could be
   * defined. This method will be called if the the original navigation target could not
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
                                 .filter(permissions::contains)
                                 .findFirst()
                                 .map(rn -> granted())
                                 .orElse(restricted(alternativeNavigationTarget(location, navigationTarget, annotation),
                                                    true));
  }


}
