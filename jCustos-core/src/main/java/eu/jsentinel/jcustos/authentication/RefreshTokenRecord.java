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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Persistent representation of a single rotating refresh token.
 * <p>
 * Hash-only; the plain value is handed to the client exactly once
 * when issued and is presented back on every token-rotation request.
 * Rotation works like this:
 *
 * <ol>
 *   <li>Issue refresh token A. {@code replacedByHash} empty.</li>
 *   <li>Client presents A, server issues access token + new refresh
 *       token B. A is updated with
 *       {@code replacedByHash = hash(B)}; B starts with
 *       {@code replacedByHash} empty.</li>
 *   <li>If A is ever presented again after step 2, it has
 *       {@code replacedByHash} set — that is the signal that someone
 *       replayed an already-rotated token. The auth flow should
 *       revoke the entire chain (the implementation handles that;
 *       this record only carries the link).</li>
 * </ol>
 *
 * @param tokenHash       non-blank token hash
 * @param tenant          tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param subjectId       subject the token authenticates
 * @param createdAt       issuance instant
 * @param expiresAt       absolute expiry, strictly after createdAt
 * @param replacedByHash  hash of the successor token, empty until
 *                        the first rotation
 * @param revokedAt       revocation instant, empty until revoked
 */
@ExperimentalJCustosApi
public record RefreshTokenRecord(
    String tokenHash,
    TenantId tenant,
    SubjectId subjectId,
    Instant createdAt,
    Instant expiresAt,
    Optional<String> replacedByHash,
    Optional<Instant> revokedAt
) {

  /**
   * Validates the record components and normalises {@code null}
   * tenant / Optionals.
   */
  public RefreshTokenRecord {
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
    replacedByHash = replacedByHash == null ? Optional.empty() : replacedByHash;
    if (replacedByHash.isPresent() && replacedByHash.get().isBlank()) {
      throw new IllegalArgumentException(
          "replacedByHash must not be blank when present");
    }
    revokedAt = revokedAt == null ? Optional.empty() : revokedAt;
    if (revokedAt.isPresent() && revokedAt.get().isBefore(createdAt)) {
      throw new IllegalArgumentException(
          "revokedAt must not predate createdAt");
    }
  }

  /**
   * Returns a copy linking this record to its successor.
   *
   * @param successorHash hash of the new token; non-blank
   * @return new record with {@code replacedByHash} set
   */
  public RefreshTokenRecord withReplacedBy(String successorHash) {
    if (successorHash == null || successorHash.isBlank()) {
      throw new IllegalArgumentException("successorHash must not be blank");
    }
    return new RefreshTokenRecord(tokenHash, tenant, subjectId,
        createdAt, expiresAt, Optional.of(successorHash), revokedAt);
  }

  /**
   * Returns a copy marked revoked at {@code at}.
   *
   * @param at revocation instant; non-null
   * @return new record with {@code revokedAt} set
   */
  public RefreshTokenRecord withRevokedAt(Instant at) {
    requireNonNull(at, "at must not be null");
    return new RefreshTokenRecord(tokenHash, tenant, subjectId,
        createdAt, expiresAt, replacedByHash, Optional.of(at));
  }

  /** Whether {@link #revokedAt()} is present. */
  public boolean isRevoked() {
    return revokedAt.isPresent();
  }

  /** Whether {@link #replacedByHash()} is present. */
  public boolean isReplaced() {
    return replacedByHash.isPresent();
  }

  /**
   * Whether the token is past expiry at {@code now}.
   *
   * @param now reference instant; non-null
   * @return whether the token is expired
   */
  public boolean isExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return !now.isBefore(expiresAt);
  }

  /**
   * Whether the token is admissible — not revoked, not replaced,
   * not expired.
   *
   * @param now reference instant; non-null
   * @return whether the token can be used for rotation
   */
  public boolean isActive(Instant now) {
    return !isRevoked() && !isReplaced() && !isExpired(now);
  }
}
