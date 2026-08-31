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
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * Predicate factories that branch on the {@link JCustosSubject} carried
 * by a {@link PolicyContext}.
 *
 * <p>All predicates return {@code false} when no subject is present,
 * except {@link #isAnonymous()} which is the explicit complement.
 */
@ExperimentalJCustosApi
public final class SubjectPredicates {

  private SubjectPredicates() {
  }

  /**
   * Matches when an authenticated subject holds the given role.
   *
   * @param roleName non-blank role identifier
   * @return predicate
   */
  public static Predicate<PolicyContext> hasRole(String roleName) {
    RoleName role = new RoleName(requireNonNull(roleName, "roleName must not be null"));
    return ctx -> ctx.subject()
        .map(s -> s.roleNames().contains(role))
        .orElse(false);
  }

  /**
   * Matches when an authenticated subject holds at least one of the
   * given roles.
   *
   * @param roleNames non-blank role identifiers; must not be empty
   * @return predicate
   */
  public static Predicate<PolicyContext> hasAnyRole(String... roleNames) {
    requireNonNull(roleNames, "roleNames must not be null");
    if (roleNames.length == 0) {
      throw new IllegalArgumentException("hasAnyRole requires at least one role");
    }
    RoleName[] roles = Arrays.stream(roleNames)
        .map(RoleName::new)
        .toArray(RoleName[]::new);
    return ctx -> {
      Optional<JCustosSubject> subject = ctx.subject();
      if (subject.isEmpty()) {
        return false;
      }
      var held = subject.get().roleNames();
      for (RoleName role : roles) {
        if (held.contains(role)) {
          return true;
        }
      }
      return false;
    };
  }

  /**
   * Matches when an authenticated subject holds the given permission.
   *
   * @param permissionName non-blank permission identifier
   * @return predicate
   */
  public static Predicate<PolicyContext> hasPermission(String permissionName) {
    PermissionName permission = new PermissionName(
        requireNonNull(permissionName, "permissionName must not be null"));
    return ctx -> ctx.subject()
        .map(s -> s.permissionNames().contains(permission))
        .orElse(false);
  }

  /**
   * Matches when no authenticated subject is bound to the context.
   *
   * @return predicate
   */
  public static Predicate<PolicyContext> isAnonymous() {
    return ctx -> ctx.subject().isEmpty();
  }
}
