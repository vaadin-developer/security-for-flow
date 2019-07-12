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
   * @param location
   * @param navigationTarget
   * @param annotation
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
