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
package com.svenruppert.vaadin.security.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;

import java.time.Clock;

import static java.util.Objects.requireNonNull;

/**
 * Bootstrap-state service backed by a {@link BootstrapStateStore}.
 * <p>
 * Where the legacy {@link BootstrapStateService} derives "is the
 * system uninitialized?" from
 * {@link AdministratorAccountStore#hasAnyAdministrator()}, this
 * variant treats the bootstrap fact as a first-class persistent
 * record (with completion instant and tenant scope). The transition
 * from "required" → "completed" is recorded by
 * {@link #markCompleted()} and is idempotent.
 *
 * <p>Bound to one {@link TenantId} + {@link BootstrapMode} at
 * construction. Multi-tenant deployments instantiate one service
 * per tenant.
 */
@ExperimentalJSentinelApi
public final class StoreBackedBootstrapStateService {

  private final BootstrapStateStore store;
  private final TenantId tenant;
  private final BootstrapMode mode;
  private final Clock clock;

  /**
   * Convenience constructor: binds to {@link TenantId#DEFAULT},
   * {@link BootstrapMode#TRANSIENT_CONSOLE} and the system clock.
   *
   * @param store backing bootstrap-state store; non-null
   */
  public StoreBackedBootstrapStateService(BootstrapStateStore store) {
    this(store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, Clock.systemUTC());
  }

  /**
   * Full constructor.
   *
   * @param store  backing bootstrap-state store; non-null
   * @param tenant tenant scope; {@code null} becomes
   *               {@link TenantId#DEFAULT}
   * @param mode   bootstrap mode; non-null. When set to
   *               {@link BootstrapMode#DISABLED}, {@link #bootstrapRequired()}
   *               always returns {@code false}
   * @param clock  time source for the completion instant; non-null
   */
  public StoreBackedBootstrapStateService(BootstrapStateStore store,
                                          TenantId tenant,
                                          BootstrapMode mode,
                                          Clock clock) {
    this.store = requireNonNull(store, "store must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.mode = requireNonNull(mode, "mode must not be null");
    this.clock = requireNonNull(clock, "clock must not be null");
  }

  /**
   * @return {@code true} when bootstrap is still required, i.e.
   *         the mode is not {@link BootstrapMode#DISABLED} and no
   *         completion has been recorded for the configured tenant
   */
  public boolean bootstrapRequired() {
    if (mode == BootstrapMode.DISABLED) {
      return false;
    }
    return !hasAdministrator();
  }

  /**
   * @return {@code true} when a completion record exists for the
   *         configured tenant. Independent of {@link BootstrapMode}
   */
  public boolean hasAdministrator() {
    return store.find(tenant)
        .map(BootstrapState::adminCreated)
        .orElse(false);
  }

  /**
   * Returns the persisted bootstrap state for the configured tenant.
   * Absent records are reported as
   * {@link BootstrapState#required(TenantId) required}.
   *
   * @return current state
   */
  public BootstrapState state() {
    return store.find(tenant).orElseGet(() -> BootstrapState.required(tenant));
  }

  /**
   * Records the completion of the initial-admin bootstrap for the
   * configured tenant at the current clock instant. Idempotent:
   * already-completed states are kept as-is so the completion
   * instant of the first transition is preserved.
   *
   * @return the persisted state after the call
   */
  public BootstrapState markCompleted() {
    BootstrapState current = state();
    if (current.adminCreated()) {
      return current;
    }
    BootstrapState completed = BootstrapState.completed(tenant, clock.instant());
    store.save(completed);
    return completed;
  }

  /**
   * Removes any recorded completion for the configured tenant.
   * Intended for tests and admin-tooling that need to "re-bootstrap"
   * a tenant (e.g. recovery flows).
   *
   * @return {@code true} when a record was removed
   */
  public boolean reset() {
    return store.delete(tenant);
  }

  /**
   * @return the {@link BootstrapMode} this service was configured
   *         with
   */
  public BootstrapMode mode() {
    return mode;
  }

  /**
   * @return the {@link TenantId} this service is bound to
   */
  public TenantId tenant() {
    return tenant;
  }
}
