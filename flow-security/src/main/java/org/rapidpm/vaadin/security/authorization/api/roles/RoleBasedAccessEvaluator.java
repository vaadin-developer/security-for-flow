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
   * @param annotation
   * @return a set of RoleName´s that are required by this annotation.
   */
  public abstract Set<RoleName> requiredRoles(T annotation);

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
