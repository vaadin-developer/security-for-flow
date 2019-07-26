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
package org.rapidpm.vaadin.security.authorization.api.roles;

import com.vaadin.flow.router.Location;
import org.rapidpm.frp.model.Result;
import org.rapidpm.vaadin.security.authorization.api.AccessEvaluator;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationService;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationServiceProvider;
import org.rapidpm.vaadin.security.authorization.api.SessionAccessor;
import org.rapidpm.vaadin.security.authorization.impl.Access;

import java.lang.annotation.Annotation;
import java.util.Set;

import static org.rapidpm.vaadin.security.authorization.impl.Access.granted;
import static org.rapidpm.vaadin.security.authorization.impl.Access.restricted;

/**
 * @param <T> Annotation on the View class , something like VisibleFor(..)
 * @param <U> The User - class
 */
public abstract class RoleBasedAccessEvaluator<T extends Annotation, U>
    implements AccessEvaluator<T> {

  private final AuthorizationService<U> authorizationService = new AuthorizationServiceProvider().load();

  /**
   * Mapping from a custom type to a defined type inside the generic implementation.
   * The Mapping could include dynamic parts, based on situation/date/time and so on.
   * For example, the Admin Role could be expanded to a set of custom specific
   * Admin Role Names.
   *
   * @param annotation the project specific annotation with the static content, something like UserRole.USER
   * @return a set of RoleName´s that are required by this annotation.
   */
  public abstract Set<RoleName> requiredRoles(T annotation);

  /**
   * based on the situation a alternative navigation target could be
   * defined. This method will be called if the the original navigation target could not
   * be ued based on missing Roles/Permissions of the active user.
   *
   * @param location actual position on the side
   * @param navigationTarget where to go next
   * @param annotation the annotation that holds the info
   * @return granted Access or a restricted one with an alternative navigation target
   */
  public abstract String alternativeNavigationTarget(Location location, Class<?> navigationTarget, T annotation);

  @Override
  public Access evaluate(Location location, Class<?> navigationTarget, T annotation) {
    final Set<RoleName> roleNames = requiredRoles(annotation);

    if (roleNames.isEmpty()) return granted();

    final Result<U> currentSubject = SessionAccessor.currentSubject();
    if (currentSubject.isAbsent())
      return restricted(alternativeNavigationTarget(location, navigationTarget, annotation), false);

    return currentSubject.stream()
                         .map(authorizationService::rolesFor)
                         .flatMap(HasRoles::roleNames)
                         .filter(roleNames::contains)
                         .findFirst()
                         .map(rn -> granted())
                         .orElse(restricted(alternativeNavigationTarget(location, navigationTarget, annotation), true));
  }
}
