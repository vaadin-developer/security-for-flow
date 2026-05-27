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

import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Generic evaluator for {@link RequiresAllPermissions} — AND-semantics
 * across the listed permissions.
 */
@ExperimentalSecurityApi
public final class RequiresAllPermissionsEvaluator
    implements AuthorizationEvaluator<RequiresAllPermissions> {

  /** Creates a new evaluator instance. */
  public RequiresAllPermissionsEvaluator() {
  }

  @Override
  public AuthorizationDecision evaluate(AccessContext context, RequiresAllPermissions annotation) {
    if (context.subject().isEmpty()) {
      return AuthorizationDecision.unauthenticated("No authenticated subject");
    }
    if (annotation.value().length == 0) {
      return AuthorizationDecision.forbidden(
          "@RequiresAllPermissions requires at least one permission");
    }

    Set<PermissionName> required = Arrays.stream(annotation.value())
        .map(PermissionName::new)
        .collect(Collectors.toUnmodifiableSet());

    boolean granted = PermissionMatcher.containsAll(
        context.subject().orElseThrow().permissionNames(),
        required);

    return granted
        ? AuthorizationDecision.granted()
        : AuthorizationDecision.forbidden("Missing required permission");
  }
}
