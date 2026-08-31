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

import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * Base implementation for permission-based access evaluation.
 *
 * @param <T> the restriction annotation type
 * @param <U> the user/subject type
 */
@ExperimentalJCustosApi("Permission-based access evaluation is experimental. "
    + "Use role-based access for stable production use.")
public abstract class PermissionBasedAccessEvaluator<T extends Annotation, U>
    implements AccessEvaluator<T> {

  /** Creates a new instance. */
  protected PermissionBasedAccessEvaluator() {
  }

  /**
   * Returns the authorization service used to resolve permissions.
   *
   * @return the authorization service
   */
  public abstract AuthorizationService<U> authorizationService();

  /**
   * Returns the currently active subject whose permissions are checked.
   *
   * @return the current subject
   */
  public abstract U activeSubject();

  /**
   * Extracts the set of required permissions from the restriction annotation.
   *
   * @param annotation the restriction annotation instance
   * @return the required permission names
   */
  public abstract Set<PermissionName> requiredPermissions(T annotation);

  /**
   * Determines the alternative navigation target when the subject
   * lacks the required permissions.
   *
   * @param context          current access context
   * @param annotation       the restriction annotation
   * @return route string for the alternative target
   */
  public abstract String alternativeNavigationTarget(AccessContext context, T annotation);

  @Override
  public AccessDecision evaluate(AccessContext context, T annotation) {
    final Set<PermissionName> permissions = requiredPermissions(annotation);

    boolean hasPermission = authorizationService()
        .permissionsFor(activeSubject())
        .permissionNames()
        .stream()
        .anyMatch(permissions::contains);

    if (hasPermission) {
      return AccessDecision.granted();
    }

    return AccessDecision.denied(
        alternativeNavigationTarget(context, annotation), true);
  }
}
