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
package eu.jsentinel.jcustos.bootstrap;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.util.Optional;

/**
 * Persistent store for {@link BootstrapState} per tenant.
 * <p>
 * Used by the first-run admin bootstrap flow to record exactly once
 * when an administrator was first created in a tenant. Where the
 * existing {@link BootstrapTokenStore} owns the short-lived
 * bootstrap <em>token</em> (a credential), this store owns the
 * long-lived bootstrap <em>state</em> (a fact).
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
public interface BootstrapStateStore {

  /**
   * Returns the recorded bootstrap state for {@code tenant}.
   *
   * @param tenant tenant scope; must not be {@code null}
   * @return state, if recorded
   */
  Optional<BootstrapState> find(TenantId tenant);

  /**
   * Persists or replaces the bootstrap state. Keyed on
   * {@link BootstrapState#tenant()}.
   *
   * @param state state to save; must not be {@code null}
   */
  void save(BootstrapState state);

  /**
   * Removes the recorded state for {@code tenant}.
   *
   * @param tenant tenant scope; must not be {@code null}
   * @return {@code true} if state was removed,
   *         {@code false} when none existed
   */
  boolean delete(TenantId tenant);
}
