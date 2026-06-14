package com.svenruppert.jsentinel.demo.skill.vaadin.security.roles;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.AccessEvaluator;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import com.svenruppert.jsentinel.authorization.navigation.AccessDecision;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;
import com.svenruppert.jsentinel.demo.skill.vaadin.views.DashboardView;
import com.svenruppert.jsentinel.demo.skill.vaadin.views.MyLoginView;

import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

/**
 * Evaluates {@link VisibleFor @VisibleFor} restrictions on route views.
 *
 * <ul>
 *   <li>No subject in the SubjectStore → reroute to login.</li>
 *   <li>Subject lacks every required role → reroute to DashboardView
 *       (Vaadin's denied-decision mapper sends the user back to a
 *       safe landing page).</li>
 *   <li>Subject has at least one required role → granted.</li>
 * </ul>
 */
public class RoleAccessEvaluator
    implements AccessEvaluator<VisibleFor>, HasLogger {

  @Override
  public AccessDecision evaluate(AccessContext context, VisibleFor annotation) {
    Set<RoleName> requiredRoles = stream(annotation.value())
        .map(Enum::name)
        .map(RoleName::new)
        .collect(Collectors.toSet());

    if (requiredRoles.isEmpty()) {
      return AccessDecision.granted();
    }

    var currentSubject = SubjectStores.subjectStore().currentSubject(User.class);
    if (currentSubject.isEmpty()) {
      return AccessDecision.denied(MyLoginView.NAV, false);
    }

    AuthorizationService<User> authorizationService =
        JSentinelServiceResolver.authorizationService();
    boolean hasRole = authorizationService.rolesFor(currentSubject.get())
        .roleNames()
        .stream()
        .anyMatch(requiredRoles::contains);

    if (hasRole) {
      return AccessDecision.granted();
    }
    return AccessDecision.denied(DashboardView.NAV, true);
  }
}
