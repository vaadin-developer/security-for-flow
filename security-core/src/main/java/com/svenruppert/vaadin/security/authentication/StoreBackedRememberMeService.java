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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * "Remember me" / persistent-login service built on top of a
 * {@link RememberMeTokenStore} and a {@link PasswordHasher}.
 * <p>
 * The plain token is generated server-side at {@link #issue} time,
 * returned to the caller exactly once (intended to ship in an
 * {@code HttpOnly; Secure} cookie or equivalent), and immediately
 * dropped — only the hash reaches the store. {@link #validate}
 * hashes the candidate the same way and queries the store by hash;
 * an attacker who exfiltrates the store cannot impersonate the
 * subject without the cookie value.
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one service per tenant.
 *
 * <p>Token entropy: 256 bits from a {@link SecureRandom}, encoded
 * as URL-safe base64 (no padding). Override via the
 * {@code tokenSource} constructor argument if a different format
 * is required by the carrier (cookie, header, query parameter).
 */
@ExperimentalSecurityApi
public final class StoreBackedRememberMeService {

  /** Default token entropy in bytes (256 bits). */
  public static final int DEFAULT_TOKEN_BYTES = 32;

  private final RememberMeTokenStore store;
  private final PasswordHasher hasher;
  private final TenantId tenant;
  private final Clock clock;
  private final Supplier<String> tokenSource;

  /**
   * Convenience constructor: binds to {@link TenantId#DEFAULT},
   * uses a system {@link Clock} and the default 256-bit token
   * source.
   *
   * @param store  backing token store; non-null
   * @param hasher password hasher used to hash tokens before
   *               persisting them; non-null
   */
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      PasswordHasher hasher) {
    this(store, hasher, TenantId.DEFAULT, Clock.systemUTC(), defaultTokenSource());
  }

  /**
   * Full constructor.
   *
   * @param store       backing token store; non-null
   * @param hasher      password hasher used to hash tokens before
   *                    persisting them; non-null
   * @param tenant      tenant scope; {@code null} becomes
   *                    {@link TenantId#DEFAULT}
   * @param clock       time source; non-null
   * @param tokenSource supplier producing the plain token strings
   *                    issued to clients; non-null and must return
   *                    non-blank values
   */
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      PasswordHasher hasher,
                                      TenantId tenant,
                                      Clock clock,
                                      Supplier<String> tokenSource) {
    this.store = requireNonNull(store, "store must not be null");
    this.hasher = requireNonNull(hasher, "hasher must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.tokenSource = requireNonNull(tokenSource, "tokenSource must not be null");
  }

  /**
   * Issues a new token for {@code subjectId} with the given TTL.
   * The plain token is returned exactly once — callers ship it to
   * the client (cookie / header) and discard it.
   *
   * @param subjectId subject the token authenticates; non-null
   * @param ttl       lifetime; must be strictly positive
   * @return issued token (plain value + record metadata)
   */
  public IssuedToken issue(SubjectId subjectId, Duration ttl) {
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(ttl, "ttl must not be null");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be strictly positive");
    }
    String plain = tokenSource.get();
    if (plain == null || plain.isBlank()) {
      throw new IllegalStateException("tokenSource produced a blank token");
    }
    Instant now = clock.instant();
    String hash = hasher.hash(plain.toCharArray());
    RememberMeTokenRecord record = new RememberMeTokenRecord(
        hash, tenant, subjectId, now, now.plus(ttl));
    store.save(record);
    return new IssuedToken(plain, record);
  }

  /**
   * Validates the supplied plain token. Returns the matching
   * record only when the hash is known, the record is in the
   * configured tenant, and the token has not expired. Expired
   * matches are removed from the store as a side effect.
   *
   * @param plainToken plain token from the carrier; null/blank
   *                   yields {@code Optional.empty()}
   * @return matching record, if valid
   */
  public Optional<RememberMeTokenRecord> validate(String plainToken) {
    if (plainToken == null || plainToken.isBlank()) {
      return Optional.empty();
    }
    String hash = hasher.hash(plainToken.toCharArray());
    Optional<RememberMeTokenRecord> match = store.findByHash(hash);
    if (match.isEmpty()) {
      return Optional.empty();
    }
    RememberMeTokenRecord record = match.get();
    if (!record.tenant().equals(tenant)) {
      return Optional.empty();
    }
    if (record.isExpired(clock.instant())) {
      store.deleteByHash(hash);
      return Optional.empty();
    }
    return Optional.of(record);
  }

  /**
   * Revokes the supplied plain token. Idempotent — unknown tokens
   * return {@code false} rather than throwing.
   *
   * @param plainToken plain token; null/blank returns {@code false}
   * @return {@code true} when a record was removed
   */
  public boolean revoke(String plainToken) {
    if (plainToken == null || plainToken.isBlank()) {
      return false;
    }
    return store.deleteByHash(hasher.hash(plainToken.toCharArray()));
  }

  /**
   * Revokes every token issued to {@code subjectId} in this
   * service's tenant.
   *
   * @param subjectId subject; non-null
   * @return number of tokens removed
   */
  public int revokeAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    return store.deleteBySubject(tenant, subjectId);
  }

  /**
   * Purges every expired token in the backing store. Spans all
   * tenants — call once globally rather than per-tenant.
   *
   * @return number of tokens purged
   */
  public int purgeExpired() {
    return store.purgeExpired(clock.instant());
  }

  private static Supplier<String> defaultTokenSource() {
    SecureRandom rng = new SecureRandom();
    return () -> {
      byte[] bytes = new byte[DEFAULT_TOKEN_BYTES];
      rng.nextBytes(bytes);
      return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    };
  }

  /**
   * Tuple returned from {@link #issue}: the plain token (caller
   * passes it to the client carrier and drops it) and the
   * persisted record (handy for tests / audit hooks).
   *
   * @param plainToken plain token value
   * @param record     persisted record (hash + metadata)
   */
  public record IssuedToken(String plainToken, RememberMeTokenRecord record) {
    /** Validates the components. */
    public IssuedToken {
      if (plainToken == null || plainToken.isBlank()) {
        throw new IllegalArgumentException("plainToken must not be blank");
      }
      requireNonNull(record, "record must not be null");
    }
  }
}
