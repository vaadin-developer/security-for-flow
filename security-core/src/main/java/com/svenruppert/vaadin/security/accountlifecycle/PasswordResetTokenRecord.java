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
package com.svenruppert.vaadin.security.accountlifecycle;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Persistent representation of a single password-reset token.
 * <p>
 * Single-use: once {@code consumedAt} is set the token must not be
 * honoured again. Stores only the <strong>hash</strong> of the
 * token; the plain value is delivered to the user (e.g. as a
 * reset-link query parameter) and never persisted.
 *
 * @param tokenHash  non-blank token hash
 * @param tenant     tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param subjectId  subject whose password the token resets
 * @param createdAt  when the token was issued
 * @param expiresAt  absolute expiry, strictly after {@code createdAt}
 * @param consumedAt instant the token was consumed, or empty when
 *                   still pending; if present must be strictly after
 *                   {@code createdAt}
 */
@ExperimentalJSentinelApi
public record PasswordResetTokenRecord(
    String tokenHash,
    TenantId tenant,
    SubjectId subjectId,
    Instant createdAt,
    Instant expiresAt,
    Optional<Instant> consumedAt
) {

  /**
   * Validates the record components and normalises {@code null}
   * tenant / {@code null} consumedAt.
   *
   * @param tokenHash  non-blank token hash
   * @param tenant     tenant scope; {@code null} becomes DEFAULT
   * @param subjectId  non-null subject
   * @param createdAt  non-null creation instant
   * @param expiresAt  non-null expiry, strictly after createdAt
   * @param consumedAt null becomes empty Optional
   */
  public PasswordResetTokenRecord {
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
    consumedAt = consumedAt == null ? Optional.empty() : consumedAt;
    if (consumedAt.isPresent() && !consumedAt.get().isAfter(createdAt)) {
      throw new IllegalArgumentException(
          "consumedAt must be strictly after createdAt");
    }
  }

  /**
   * Returns a copy with {@link #consumedAt()} set to {@code at} —
   * the canonical way to mark a token consumed.
   *
   * @param at instant the token was consumed; must not be {@code null}
   * @return new record with {@code consumedAt = Optional.of(at)}
   */
  public PasswordResetTokenRecord withConsumedAt(Instant at) {
    requireNonNull(at, "at must not be null");
    return new PasswordResetTokenRecord(
        tokenHash, tenant, subjectId, createdAt, expiresAt, Optional.of(at));
  }

  /**
   * Returns whether the token has been consumed.
   *
   * @return {@code true} when consumedAt is present
   */
  public boolean isConsumed() {
    return consumedAt.isPresent();
  }

  /**
   * Returns {@code true} when the token is past its expiry at the
   * supplied instant.
   *
   * @param now reference instant; non-null
   * @return whether the token is expired
   */
  public boolean isExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return !now.isBefore(expiresAt);
  }
}
