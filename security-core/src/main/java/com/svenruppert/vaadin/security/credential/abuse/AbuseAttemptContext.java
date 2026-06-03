/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.vaadin.security.credential.abuse;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Adapter-neutral attempt context passed into
 * {@link AbuseDetectionService#evaluate} and
 * {@link AbuseDetectionService#recordOutcome}.
 *
 * <p>Every field is structural: usernames are stored verbatim,
 * client addresses are opaque strings, the tenant defaults to
 * {@link TenantId#DEFAULT}. No password or token material ever
 * appears here (CWE-209 / CWE-522).</p>
 *
 * @param attemptType    what the caller is about to do
 * @param username       optional — login/password-change attempts
 *                       always know it, an anonymous reset request
 *                       might not
 * @param clientAddress  optional — best-effort remote identifier
 * @param tenant         {@link TenantId#DEFAULT} for single-tenant
 *                       deployments
 * @param at             attempt timestamp; the service does not call
 *                       {@link Instant#now} on its own
 */
public record AbuseAttemptContext(
    AbuseAttemptType attemptType,
    Optional<String> username,
    Optional<String> clientAddress,
    TenantId tenant,
    Instant at
) {

  public AbuseAttemptContext {
    Objects.requireNonNull(attemptType, "attemptType");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(clientAddress, "clientAddress");
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(at, "at");
  }
}
