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
package com.svenruppert.vaadin.security.ratelimiting;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;

/**
 * Composite key under which {@link RateLimitStore} tracks event
 * timestamps for sliding-window rate-limiting.
 * <p>
 * The {@code scope} component is a free-form string that the policy
 * layer (planned for V00.70 Phase 7c) composes from whatever
 * dimensions the application wants to limit on — typical examples:
 * <ul>
 *   <li>{@code "ip:1.2.3.4"} — per source IP.</li>
 *   <li>{@code "subject:alice"} — per authenticated user.</li>
 *   <li>{@code "endpoint:POST /api/login"} — per HTTP endpoint.</li>
 *   <li>{@code "ip:1.2.3.4|endpoint:POST /api/login"} — combined.</li>
 * </ul>
 *
 * <p>Keeping the {@code scope} as an opaque string keeps the store
 * itself dimension-agnostic; the policy decides naming conventions
 * and is free to evolve them without changing the store contract.
 *
 * @param tenant tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param scope  non-blank dimension string
 */
@ExperimentalJSentinelApi
public record RateLimitKey(TenantId tenant, String scope) {

  /**
   * Validates the record components and normalises a {@code null}
   * tenant to {@link TenantId#DEFAULT}.
   *
   * @param tenant tenant scope; {@code null} becomes DEFAULT
   * @param scope  non-blank scope
   */
  public RateLimitKey {
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    if (scope == null || scope.isBlank()) {
      throw new IllegalArgumentException("scope must not be blank");
    }
  }
}
