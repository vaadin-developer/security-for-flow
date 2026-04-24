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
package com.svenruppert.vaadin.security.demo.app.security.roles;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SessionAccessor;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AuthorizationDecision;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.views.MainView;
import com.svenruppert.vaadin.security.demo.app.views.MyLoginView;
import com.vaadin.flow.router.Location;

import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

/**
 * Role-based access evaluator for the demo application.
 */
public class MyRoleAccessEvaluator
    implements AccessEvaluator<VisibleFor>, HasLogger {

  @Override
  public AuthorizationDecision evaluateAccess(
      Location location, Class<?> navigationTarget, VisibleFor annotation) {

    Set<RoleName> requiredRoles = stream(annotation.value())
        .map(Enum::name)
        .map(RoleName::new)
        .collect(Collectors.toSet());

    if (requiredRoles.isEmpty()) {
      return AuthorizationDecision.granted();
    }

    var currentSubject = SessionAccessor.<MyUser>currentSubject();
    if (currentSubject.isAbsent()) {
      return AuthorizationDecision.denied(MyLoginView.NAV, false);
    }

    AuthorizationService<MyUser> authorizationService =
        SecurityServiceResolver.authorizationService();
    boolean hasRole = authorizationService.rolesFor(currentSubject.get())
        .roleNames()
        .stream()
        .anyMatch(requiredRoles::contains);

    if (hasRole) {
      return AuthorizationDecision.granted();
    }

    return AuthorizationDecision.denied(MainView.NAV, true);
  }
}
