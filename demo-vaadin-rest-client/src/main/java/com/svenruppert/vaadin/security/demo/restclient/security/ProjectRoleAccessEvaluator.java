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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleMatcher;
import com.svenruppert.vaadin.security.autoservice.api.JSentinelAutoService;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/** Evaluator for the project-specific {@link VisibleForRoles} annotation. */
@JSentinelAutoService(AuthorizationEvaluator.class)
public final class ProjectRoleAccessEvaluator implements AuthorizationEvaluator<VisibleForRoles> {

  @Override
  public AuthorizationDecision evaluate(AccessContext context, VisibleForRoles annotation) {
    if (context.subject().isEmpty()) {
      return AuthorizationDecision.unauthenticated("No authenticated subject");
    }
    Set<RoleName> required = Arrays.stream(annotation.value())
        .map(ProjectRole::roleName)
        .collect(Collectors.toUnmodifiableSet());
    boolean granted = RoleMatcher.containsAny(
        context.subject().orElseThrow().roleNames(),
        required);
    return granted
        ? AuthorizationDecision.granted()
        : AuthorizationDecision.forbidden("Missing required role");
  }
}
