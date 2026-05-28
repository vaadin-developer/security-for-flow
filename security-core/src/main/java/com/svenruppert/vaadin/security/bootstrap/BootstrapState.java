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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Persistent first-run-bootstrap state for one tenant.
 * <p>
 * Today's {@code InitialAdminBootstrapService} keeps the bootstrap
 * flag inside an {@link AdministratorAccountStore} ("does any
 * administrator exist?") and uses the existence of an administrator
 * as the bootstrap-completed signal. That works for a single-tenant
 * single-process deployment but does not carry the "when" or any
 * tenant scoping, which a multi-tenant deployment needs.
 *
 * <p>{@link BootstrapStateStore} owns one {@code BootstrapState} per
 * tenant; transitioning from {@link #adminCreated()} {@code false} to
 * {@code true} happens exactly once per tenant (the moment the
 * initial admin is created). The transition is recorded by saving a
 * new {@code BootstrapState} with the completion instant.
 *
 * @param tenant         tenant scope; {@code null} becomes
 *                       {@link TenantId#DEFAULT}
 * @param adminCreated   {@code true} once the initial admin has been
 *                       created for this tenant
 * @param adminCreatedAt completion instant; required when
 *                       {@code adminCreated} is {@code true}, must
 *                       be empty when it is {@code false}
 */
@ExperimentalSecurityApi
public record BootstrapState(
    TenantId tenant,
    boolean adminCreated,
    Optional<Instant> adminCreatedAt
) {

  /**
   * Validates record invariants.
   *
   * @param tenant         tenant scope; {@code null} becomes DEFAULT
   * @param adminCreated   completion flag
   * @param adminCreatedAt completion instant; null becomes empty;
   *                       presence must match {@code adminCreated}
   */
  public BootstrapState {
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    adminCreatedAt = adminCreatedAt == null ? Optional.empty() : adminCreatedAt;
    if (adminCreated && adminCreatedAt.isEmpty()) {
      throw new IllegalArgumentException(
          "adminCreatedAt must be present when adminCreated is true");
    }
    if (!adminCreated && adminCreatedAt.isPresent()) {
      throw new IllegalArgumentException(
          "adminCreatedAt must be empty when adminCreated is false");
    }
  }

  /**
   * Builds the "bootstrap still required" state for {@code tenant}.
   *
   * @param tenant tenant scope
   * @return required-state
   */
  public static BootstrapState required(TenantId tenant) {
    return new BootstrapState(tenant, false, Optional.empty());
  }

  /**
   * Builds the "bootstrap completed" state for {@code tenant}.
   *
   * @param tenant tenant scope
   * @param at     completion instant; must not be {@code null}
   * @return completed-state
   */
  public static BootstrapState completed(TenantId tenant, Instant at) {
    requireNonNull(at, "at must not be null");
    return new BootstrapState(tenant, true, Optional.of(at));
  }
}
