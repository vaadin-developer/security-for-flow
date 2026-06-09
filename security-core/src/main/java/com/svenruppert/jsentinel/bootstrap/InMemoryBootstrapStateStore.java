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
package com.svenruppert.jsentinel.bootstrap;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link BootstrapStateStore} backed by a
 * {@link ConcurrentHashMap} keyed on {@link TenantId}.
 */
@ExperimentalJSentinelApi
public final class InMemoryBootstrapStateStore implements BootstrapStateStore {

  private final ConcurrentHashMap<TenantId, BootstrapState> states =
      new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryBootstrapStateStore() {
  }

  @Override
  public Optional<BootstrapState> find(TenantId tenant) {
    requireNonNull(tenant, "tenant must not be null");
    return Optional.ofNullable(states.get(tenant));
  }

  @Override
  public void save(BootstrapState state) {
    requireNonNull(state, "state must not be null");
    states.put(state.tenant(), state);
  }

  @Override
  public boolean delete(TenantId tenant) {
    requireNonNull(tenant, "tenant must not be null");
    return states.remove(tenant) != null;
  }
}
