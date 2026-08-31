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

import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Generic evaluator for {@link RequiresPermission}.
 */
public final class RequiresPermissionEvaluator implements AuthorizationEvaluator<RequiresPermission> {

  @Override
  public AuthorizationDecision evaluate(AccessContext context, RequiresPermission annotation) {
    if (context.subject().isEmpty()) {
      return AuthorizationDecision.unauthenticated("No authenticated subject");
    }
    // JS-SEC-010 (CWE-863): an empty @RequiresPermission({}) must fail closed.
    // An empty required set makes PermissionMatcher.containsAll vacuously true,
    // which would grant to any authenticated subject regardless of permissions.
    // Mirror the fail-closed siblings (RequiresAll/AnyPermissionsEvaluator).
    if (annotation.value().length == 0) {
      return AuthorizationDecision.forbidden(
          "@RequiresPermission requires at least one permission");
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
