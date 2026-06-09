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
package com.svenruppert.jsentinel.authorization.api.roles;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Set;

/**
 * Application-provided role inheritance graph.
 * <p>
 * Returns the set of roles implied by a single held role. The
 * implication is transitive: an {@code ADMIN} that inherits from
 * {@code EDITOR}, which itself inherits from {@code VIEWER}, must
 * return both {@code EDITOR} and {@code VIEWER} (plus itself) from
 * {@link #impliedRoles(RoleName) impliedRoles(ADMIN)}.
 *
 * <p>Discovered via {@code java.util.ServiceLoader}; if no SPI is
 * registered, the framework falls back to a no-op hierarchy that
 * implies only the role itself (i.e. no inheritance).
 *
 * <p>Implementations must be thread-safe and side-effect-free —
 * {@link #impliedRoles(RoleName)} runs on every role-based admission
 * check.
 */
@ExperimentalJSentinelApi
public interface RoleHierarchy {

  /**
   * Returns the closure of roles implied by the given held role.
   * The returned set always contains the held role itself.
   *
   * @param held a single role held by the subject; never {@code null}
   * @return non-empty, read-only set including {@code held} plus
   *         every role transitively inherited from it
   */
  Set<RoleName> impliedRoles(RoleName held);

  /**
   * Convenience: returns {@code true} when {@code held} implies
   * {@code required}, either by identity or via the inheritance
   * graph.
   *
   * @param held     a single role held by the subject
   * @param required a single role demanded by an admission rule
   * @return {@code true} if {@code held} satisfies {@code required}
   */
  default boolean impliesRole(RoleName held, RoleName required) {
    return impliedRoles(held).contains(required);
  }
}
