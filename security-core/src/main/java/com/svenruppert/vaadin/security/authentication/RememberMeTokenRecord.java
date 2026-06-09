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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Persistent representation of a single "remember me" token.
 * <p>
 * Stores only the <strong>hash</strong> of the token, never the
 * plain value: the plain token lives in a cookie on the user's
 * device and must not be reconstructable from the store.
 * Implementations of
 * {@link com.svenruppert.vaadin.security.authentication.RememberMeTokenStore}
 * keep the same hashing convention they apply at lookup time.
 *
 * <p>{@code expiresAt} is the absolute expiry instant; auth flows
 * compare it to {@link Instant#now()} (or a clock-injected
 * equivalent) and reject the token outside the validity window.
 *
 * @param tokenHash  non-blank token hash; the plain token is never
 *                   stored
 * @param tenant     tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param subjectId  authenticated subject the token grants
 * @param createdAt  when the token was issued
 * @param expiresAt  absolute expiry; must be strictly after
 *                   {@code createdAt}
 */
@ExperimentalJSentinelApi
public record RememberMeTokenRecord(
    String tokenHash,
    TenantId tenant,
    SubjectId subjectId,
    Instant createdAt,
    Instant expiresAt
) {

  /**
   * Validates the record components and normalises {@code null}
   * tenant to {@link TenantId#DEFAULT}.
   *
   * @param tokenHash non-blank token hash
   * @param tenant    tenant scope; {@code null} becomes DEFAULT
   * @param subjectId non-null subject
   * @param createdAt non-null creation instant
   * @param expiresAt non-null expiry instant, strictly after createdAt
   */
  public RememberMeTokenRecord {
    if (tokenHash == null || tokenHash.isBlank()) {
      throw new IllegalArgumentException("tokenHash must not be blank");
    }
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(createdAt, "createdAt must not be null");
    requireNonNull(expiresAt, "expiresAt must not be null");
    if (!expiresAt.isAfter(createdAt)) {
      throw new IllegalArgumentException(
          "expiresAt must be strictly after createdAt");
    }
  }

  /**
   * Returns {@code true} when the token is past its expiry at the
   * supplied instant.
   *
   * @param now reference instant; must not be {@code null}
   * @return whether the token is expired
   */
  public boolean isExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return !now.isBefore(expiresAt);
  }
}
