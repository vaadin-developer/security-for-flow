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
package eu.jsentinel.jcustos.accountlifecycle;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Persistent representation of a single email-verification token.
 * <p>
 * Carries the email address the token confirms — different from a
 * password-reset record, where the address is implicit in the
 * subject. Single-use, hash-only, identical lifecycle shape to
 * {@link PasswordResetTokenRecord}.
 *
 * @param tokenHash  non-blank token hash
 * @param tenant     tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param subjectId  subject whose email the token verifies
 * @param email      non-blank email address being verified
 * @param createdAt  when the token was issued
 * @param expiresAt  absolute expiry, strictly after {@code createdAt}
 * @param consumedAt instant the token was consumed, or empty when
 *                   still pending; if present must be strictly after
 *                   {@code createdAt}
 */
@ExperimentalJCustosApi
public record EmailVerificationTokenRecord(
    String tokenHash,
    TenantId tenant,
    SubjectId subjectId,
    String email,
    Instant createdAt,
    Instant expiresAt,
    Optional<Instant> consumedAt
) {

  /**
   * Validates the record components and normalises {@code null}
   * tenant / consumedAt.
   *
   * @param tokenHash  non-blank token hash
   * @param tenant     {@code null} becomes DEFAULT
   * @param subjectId  non-null subject
   * @param email      non-blank email
   * @param createdAt  non-null creation instant
   * @param expiresAt  non-null expiry, strictly after createdAt
   * @param consumedAt null becomes empty Optional
   */
  public EmailVerificationTokenRecord {
    if (tokenHash == null || tokenHash.isBlank()) {
      throw new IllegalArgumentException("tokenHash must not be blank");
    }
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(subjectId, "subjectId must not be null");
    if (email == null || email.isBlank()) {
      throw new IllegalArgumentException("email must not be blank");
    }
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
   * Returns a copy with {@link #consumedAt()} set to {@code at}.
   *
   * @param at instant the token was consumed; non-null
   * @return new record with {@code consumedAt = Optional.of(at)}
   */
  public EmailVerificationTokenRecord withConsumedAt(Instant at) {
    requireNonNull(at, "at must not be null");
    return new EmailVerificationTokenRecord(
        tokenHash, tenant, subjectId, email,
        createdAt, expiresAt, Optional.of(at));
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
