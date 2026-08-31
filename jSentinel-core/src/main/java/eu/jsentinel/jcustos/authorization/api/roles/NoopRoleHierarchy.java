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
package eu.jsentinel.jcustos.authorization.api.roles;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Default {@link RoleHierarchy}: a held role implies only itself.
 * <p>
 * Equivalent to the pre-hierarchy semantics where role-based
 * admission was a plain set membership check. Returned by
 * {@code JSentinelServiceResolver.roleHierarchy()} when no SPI
 * implementation is registered, so existing applications keep their
 * exact behaviour after the upgrade.
 */
@ExperimentalJSentinelApi
public final class NoopRoleHierarchy implements RoleHierarchy {

  /** Shared singleton instance — the hierarchy is stateless. */
  public static final NoopRoleHierarchy INSTANCE = new NoopRoleHierarchy();

  private NoopRoleHierarchy() {
  }

  @Override
  public Set<RoleName> impliedRoles(RoleName held) {
    return Set.of(requireNonNull(held, "held must not be null"));
  }
}
