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
package com.svenruppert.vaadin.security.authentication;

import com.svenruppert.vaadin.security.audit.ApiKeyDenied;
import com.svenruppert.vaadin.security.audit.ApiKeyUsed;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Authentication facade for long-lived API keys, sitting on top of
 * an {@link ApiKeyStore} + {@link PasswordHasher}.
 * <p>
 * {@link #authenticate(String) authenticate(plainKey)} hashes the
 * candidate with the {@link PasswordHasher} (the same shape works:
 * {@code hash(char[]) → String}), looks the record up in the
 * store, applies the lifecycle invariants
 * ({@link ApiKeyRecord#isActive isActive}) and:
 * <ul>
 *   <li>on success: updates {@code lastUsedAt}, publishes
 *       {@link ApiKeyUsed}, returns the record;</li>
 *   <li>on failure: publishes {@link ApiKeyDenied} with a short
 *       reason ({@code "Unknown"}, {@code "ForeignTenant"},
 *       {@code "Revoked"}, {@code "Expired"}) and returns
 *       {@link Optional#empty()}.</li>
 * </ul>
 *
 * <p>The caller (REST adapter / app code) reads the returned
 * record's {@link ApiKeyRecord#scopes() scopes} and treats them as
 * the permission set granted by the request. The framework does
 * not narrow the subject's standing permissions further — scopes
 * are the entire authorization surface of an API-key request.
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one service per tenant.
 */
@ExperimentalSecurityApi
public final class ApiKeyAuthenticationService {

  private final ApiKeyStore store;
  private final PasswordHasher hasher;
  private final SecurityAuditService auditService;
  private final TenantId tenant;
  private final Clock clock;

  /**
   * Convenience constructor: tenant {@link TenantId#DEFAULT},
   * system clock.
   *
   * @param store        API-key store; non-null
   * @param hasher       hasher used to hash plain keys for lookup; non-null
   * @param auditService audit sink; non-null
   */
  public ApiKeyAuthenticationService(ApiKeyStore store,
                                     PasswordHasher hasher,
                                     SecurityAuditService auditService) {
    this(store, hasher, auditService, TenantId.DEFAULT, Clock.systemUTC());
  }

  /**
   * Full constructor.
   *
   * @param store        API-key store; non-null
   * @param hasher       hasher used to hash plain keys for lookup; non-null
   * @param auditService audit sink; non-null
   * @param tenant       tenant scope; {@code null} becomes
   *                     {@link TenantId#DEFAULT}
   * @param clock        time source; non-null
   */
  public ApiKeyAuthenticationService(ApiKeyStore store,
                                     PasswordHasher hasher,
                                     SecurityAuditService auditService,
                                     TenantId tenant,
                                     Clock clock) {
    this.store = requireNonNull(store, "store must not be null");
    this.hasher = requireNonNull(hasher, "hasher must not be null");
    this.auditService = requireNonNull(auditService, "auditService must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
  }

  /**
   * Authenticates the supplied plain key.
   *
   * @param plainKey plain key value (from a header / cookie);
   *                 null/blank yields empty
   * @return active record on success, empty on every failure mode
   */
  public Optional<ApiKeyRecord> authenticate(String plainKey) {
    if (plainKey == null || plainKey.isBlank()) {
      return Optional.empty();
    }
    String hash = hasher.hash(plainKey.toCharArray());
    Optional<ApiKeyRecord> match = store.findByHash(hash);
    if (match.isEmpty()) {
      publishDenied(hash, "", "Unknown");
      return Optional.empty();
    }
    ApiKeyRecord record = match.get();
    if (!record.tenant().equals(tenant)) {
      publishDenied(hash, record.subjectId().value(), "ForeignTenant");
      return Optional.empty();
    }
    Instant now = clock.instant();
    if (record.isRevoked()) {
      publishDenied(hash, record.subjectId().value(), "Revoked");
      return Optional.empty();
    }
    if (record.isExpired(now)) {
      publishDenied(hash, record.subjectId().value(), "Expired");
      return Optional.empty();
    }
    // Touch last-used; persist via store. Failure here must not
    // turn a successful authentication into a denial.
    try {
      store.markUsed(hash, now);
    } catch (RuntimeException ignored) {
      // store hiccup; carry on with the in-memory record
    }
    publishUsed(now, record);
    return Optional.of(record.withLastUsedAt(now));
  }

  private void publishUsed(Instant at, ApiKeyRecord record) {
    try {
      auditService.publish(new ApiKeyUsed(
          at, record.subjectId().value(), record.name(), record.keyHash()));
    } catch (RuntimeException ignored) {
      // sinks must not block authentication
    }
  }

  private void publishDenied(String hash, String subjectId, String reason) {
    try {
      auditService.publish(new ApiKeyDenied(
          clock.instant(), subjectId, hash, reason));
    } catch (RuntimeException ignored) {
      // sinks must not block authentication
    }
  }
}
