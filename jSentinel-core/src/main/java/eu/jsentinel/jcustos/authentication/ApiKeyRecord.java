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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Persistent representation of a single long-lived API key.
 * <p>
 * Stores only the <strong>hash</strong> of the key; the plain value
 * is shown to the user exactly once at creation time and never
 * persisted. Each key carries its own scope set — usually a subset
 * of the issuing subject's permissions, narrowed to the operations
 * the key holder needs.
 *
 * <p>Lifecycle states reachable through the {@code with…} helpers:
 * <ul>
 *   <li>fresh — {@code lastUsedAt} + {@code revokedAt} empty.</li>
 *   <li>used — {@code lastUsedAt} present, {@code revokedAt} empty;
 *       {@link #isActive(Instant)} still {@code true}.</li>
 *   <li>revoked — {@code revokedAt} present; {@link #isActive(Instant)}
 *       always {@code false} thereafter.</li>
 *   <li>expired — {@code expiresAt} present and {@code now >=
 *       expiresAt}; {@link #isActive(Instant)} also {@code false}.</li>
 * </ul>
 *
 * @param keyHash    non-blank API-key hash
 * @param tenant     tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param subjectId  subject that issued the key
 * @param name       non-blank human-readable label
 * @param scopes     immutable permission set the key grants;
 *                   {@code null} becomes empty
 * @param createdAt  issuance instant
 * @param expiresAt  absolute expiry; if present must be strictly
 *                   after {@code createdAt}; empty for keys without
 *                   expiry
 * @param lastUsedAt last successful authentication; if present must
 *                   not predate {@code createdAt}
 * @param revokedAt  revocation instant; if present must not predate
 *                   {@code createdAt}
 */
@ExperimentalJSentinelApi
public record ApiKeyRecord(
    String keyHash,
    TenantId tenant,
    SubjectId subjectId,
    String name,
    Set<PermissionName> scopes,
    Instant createdAt,
    Optional<Instant> expiresAt,
    Optional<Instant> lastUsedAt,
    Optional<Instant> revokedAt
) {

  /**
   * Validates the record components, normalises {@code null} tenant
   * to {@link TenantId#DEFAULT}, defensively copies {@code scopes},
   * and replaces {@code null} Optionals with {@link Optional#empty()}.
   */
  public ApiKeyRecord {
    if (keyHash == null || keyHash.isBlank()) {
      throw new IllegalArgumentException("keyHash must not be blank");
    }
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(subjectId, "subjectId must not be null");
    if (name == null || name.isBlank()) {
      throw new IllegalArgumentException("name must not be blank");
    }
    scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
    requireNonNull(createdAt, "createdAt must not be null");
    expiresAt = expiresAt == null ? Optional.empty() : expiresAt;
    if (expiresAt.isPresent() && !expiresAt.get().isAfter(createdAt)) {
      throw new IllegalArgumentException(
          "expiresAt must be strictly after createdAt");
    }
    lastUsedAt = lastUsedAt == null ? Optional.empty() : lastUsedAt;
    if (lastUsedAt.isPresent() && lastUsedAt.get().isBefore(createdAt)) {
      throw new IllegalArgumentException(
          "lastUsedAt must not predate createdAt");
    }
    revokedAt = revokedAt == null ? Optional.empty() : revokedAt;
    if (revokedAt.isPresent() && revokedAt.get().isBefore(createdAt)) {
      throw new IllegalArgumentException(
          "revokedAt must not predate createdAt");
    }
  }

  /**
   * Returns a copy with {@link #lastUsedAt()} set to {@code at}.
   *
   * @param at instant the key was used; non-null
   * @return new record
   */
  public ApiKeyRecord withLastUsedAt(Instant at) {
    requireNonNull(at, "at must not be null");
    return new ApiKeyRecord(keyHash, tenant, subjectId, name, scopes,
        createdAt, expiresAt, Optional.of(at), revokedAt);
  }

  /**
   * Returns a copy with {@link #revokedAt()} set to {@code at}.
   *
   * @param at instant the key was revoked; non-null
   * @return new record
   */
  public ApiKeyRecord withRevokedAt(Instant at) {
    requireNonNull(at, "at must not be null");
    return new ApiKeyRecord(keyHash, tenant, subjectId, name, scopes,
        createdAt, expiresAt, lastUsedAt, Optional.of(at));
  }

  /** Whether {@link #revokedAt()} is present. */
  public boolean isRevoked() {
    return revokedAt.isPresent();
  }

  /**
   * Whether the key is expired at {@code now}. A key without an
   * {@link #expiresAt()} value never expires.
   *
   * @param now reference instant; non-null
   * @return whether the key is expired
   */
  public boolean isExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return expiresAt.isPresent() && !now.isBefore(expiresAt.get());
  }

  /**
   * Whether the key is admissible at {@code now} — neither revoked
   * nor expired.
   *
   * @param now reference instant; non-null
   * @return whether the key can authenticate
   */
  public boolean isActive(Instant now) {
    return !isRevoked() && !isExpired(now);
  }
}
