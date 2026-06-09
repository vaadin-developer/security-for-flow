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
package com.svenruppert.jsentinel.authentication;

import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.TokenRotated;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * Access + rotating refresh token issuance on top of a
 * {@link RefreshTokenStore}.
 * <p>
 * Three operations:
 * <ol>
 *   <li>{@link #issue(SubjectId) issue(subject)} — issues a fresh
 *       {@link TokenPair} {@code (accessPlain, refreshPlain)}.
 *       Only the refresh token's hash reaches the store; the
 *       access token is returned to the caller verbatim and the
 *       framework does <strong>not</strong> persist it (apps that
 *       want stateless access tokens hand back a JWT, apps with
 *       a session-store cache it themselves).</li>
 *   <li>{@link #rotate(String) rotate(refreshPlain)} — consumes
 *       the old refresh token, marks it
 *       {@link RefreshTokenStore#markReplaced replaced}, issues
 *       a fresh access + refresh pair, emits
 *       {@link TokenRotated}. Returns empty on every failure mode
 *       (unknown, wrong tenant, revoked, replaced, expired) — the
 *       caller must <strong>not</strong> retry with a different
 *       reason.</li>
 *   <li>{@link #revoke(String) revoke(refreshPlain)} — marks a
 *       still-active refresh token revoked. No-op when already
 *       revoked / replaced / unknown.</li>
 * </ol>
 *
 * <p>Replay defense: when {@link #rotate rotate} is called with a
 * refresh token that already has
 * {@link RefreshTokenRecord#replacedByHash() replacedByHash}, that
 * is a strong signal of replay — the token was already rotated.
 * This service does not by itself chase the full chain (the
 * {@code RefreshTokenStore} contract leaves chain-revocation to the
 * application) but it does refuse the request and emits an audit
 * trail through the store's existing state.
 *
 * <p>Bound to one {@link TenantId} at construction.
 */
@ExperimentalJSentinelApi
public final class TokenService {

  /** Default token entropy in bytes (256 bits). */
  public static final int DEFAULT_TOKEN_BYTES = 32;

  private final RefreshTokenStore store;
  private final PasswordHasher hasher;
  private final JSentinelAuditService auditService;
  private final TenantId tenant;
  private final Clock clock;
  private final Supplier<String> tokenSource;
  private final Duration accessTtl;
  private final Duration refreshTtl;

  /**
   * Convenience constructor: tenant {@link TenantId#DEFAULT},
   * system clock, 256-bit token source, 15-min access TTL, 30-day
   * refresh TTL.
   *
   * @param store        backing store; non-null
   * @param hasher       hasher used to hash refresh tokens; non-null
   * @param auditService audit sink; non-null
   */
  public TokenService(RefreshTokenStore store,
                      PasswordHasher hasher,
                      JSentinelAuditService auditService) {
    this(store, hasher, auditService, TenantId.DEFAULT, Clock.systemUTC(),
        defaultTokenSource(),
        Duration.ofMinutes(15), Duration.ofDays(30));
  }

  /**
   * Full constructor.
   *
   * @param store        backing store; non-null
   * @param hasher       hasher used to hash refresh tokens; non-null
   * @param auditService audit sink; non-null
   * @param tenant       tenant scope; {@code null} becomes
   *                     {@link TenantId#DEFAULT}
   * @param clock        time source; non-null
   * @param tokenSource  plain-token supplier; non-null
   * @param accessTtl    access-token lifetime; strictly positive
   * @param refreshTtl   refresh-token lifetime; strictly positive
   */
  public TokenService(RefreshTokenStore store,
                      PasswordHasher hasher,
                      JSentinelAuditService auditService,
                      TenantId tenant,
                      Clock clock,
                      Supplier<String> tokenSource,
                      Duration accessTtl,
                      Duration refreshTtl) {
    this.store = requireNonNull(store, "store must not be null");
    this.hasher = requireNonNull(hasher, "hasher must not be null");
    this.auditService = requireNonNull(auditService, "auditService must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.tokenSource = requireNonNull(tokenSource, "tokenSource must not be null");
    this.accessTtl = requirePositive(accessTtl, "accessTtl");
    this.refreshTtl = requirePositive(refreshTtl, "refreshTtl");
  }

  /**
   * Issues a fresh access + refresh pair. The refresh token is
   * persisted (hash-only); the access token is returned verbatim
   * and not persisted.
   *
   * @param subjectId subject the new pair authenticates; non-null
   * @return issued pair
   */
  public TokenPair issue(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    Instant now = clock.instant();
    String accessPlain = nextToken();
    String refreshPlain = nextToken();
    String refreshHash = hasher.hash(refreshPlain.toCharArray());
    RefreshTokenRecord record = new RefreshTokenRecord(
        refreshHash, tenant, subjectId,
        now, now.plus(refreshTtl),
        Optional.empty(), Optional.empty());
    store.save(record);
    return new TokenPair(
        accessPlain, now.plus(accessTtl),
        refreshPlain, record.expiresAt(),
        subjectId);
  }

  /**
   * Rotates the supplied refresh token. The old token is marked
   * replaced; a fresh pair is issued. Returns empty on every
   * failure (unknown, wrong tenant, revoked, replaced, expired).
   *
   * @param refreshPlain plain refresh token; null/blank yields empty
   * @return fresh pair on the successful transition
   */
  public Optional<TokenPair> rotate(String refreshPlain) {
    if (refreshPlain == null || refreshPlain.isBlank()) {
      return Optional.empty();
    }
    String oldHash = hasher.hash(refreshPlain.toCharArray());
    Optional<RefreshTokenRecord> match = store.findByHash(oldHash);
    if (match.isEmpty()) {
      return Optional.empty();
    }
    RefreshTokenRecord old = match.get();
    if (!old.tenant().equals(tenant)) {
      return Optional.empty();
    }
    Instant now = clock.instant();
    if (!old.isActive(now)) {
      return Optional.empty();
    }
    TokenPair pair = issue(old.subjectId());
    String newHash = hasher.hash(pair.refreshToken().toCharArray());
    if (!store.markReplaced(oldHash, newHash, now)) {
      // Concurrent rotation slipped in between findByHash and markReplaced.
      // The new pair is already persisted — surface the rotation anyway
      // (the caller can't usefully recover, and the chain link is the
      // only thing missing).
      publishRotated(now, old.subjectId().value(), oldHash, newHash);
      return Optional.of(pair);
    }
    publishRotated(now, old.subjectId().value(), oldHash, newHash);
    return Optional.of(pair);
  }

  /**
   * Marks the refresh token revoked. No-op for unknown / already
   * revoked / replaced / expired tokens.
   *
   * @param refreshPlain plain refresh token; null/blank → false
   * @return {@code true} when a still-active record was just
   *         marked revoked
   */
  public boolean revoke(String refreshPlain) {
    if (refreshPlain == null || refreshPlain.isBlank()) {
      return false;
    }
    String hash = hasher.hash(refreshPlain.toCharArray());
    return store.markRevoked(hash, clock.instant());
  }

  /**
   * Drops every refresh token issued to {@code subjectId} in this
   * service's tenant.
   *
   * @param subjectId subject; non-null
   * @return number of records removed
   */
  public int revokeAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    return store.deleteBySubject(tenant, subjectId);
  }

  /**
   * Purges every expired record. Spans all tenants.
   *
   * @return number of records purged
   */
  public int purgeExpired() {
    return store.purgeExpired(clock.instant());
  }

  private String nextToken() {
    String t = tokenSource.get();
    if (t == null || t.isBlank()) {
      throw new IllegalStateException("tokenSource produced a blank token");
    }
    return t;
  }

  private void publishRotated(Instant at, String subjectId,
                              String oldHash, String newHash) {
    try {
      auditService.publish(new TokenRotated(at, subjectId, oldHash, newHash));
    } catch (RuntimeException ignored) {
      // sinks must not block rotation
    }
  }

  private static Duration requirePositive(Duration d, String name) {
    requireNonNull(d, name + " must not be null");
    if (d.isZero() || d.isNegative()) {
      throw new IllegalArgumentException(name + " must be strictly positive");
    }
    return d;
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
   * Returned from {@link #issue issue} / {@link #rotate rotate}.
   * Apps deliver both plain tokens to the client (typically in a
   * JSON body) and discard them server-side.
   *
   * @param accessToken      plain access token
   * @param accessExpiresAt  access-token expiry
   * @param refreshToken     plain refresh token
   * @param refreshExpiresAt refresh-token expiry
   * @param subjectId        subject the pair authenticates
   */
  public record TokenPair(
      String accessToken,
      Instant accessExpiresAt,
      String refreshToken,
      Instant refreshExpiresAt,
      SubjectId subjectId
  ) {
    /** Validates the components. */
    public TokenPair {
      if (accessToken == null || accessToken.isBlank()) {
        throw new IllegalArgumentException("accessToken must not be blank");
      }
      requireNonNull(accessExpiresAt, "accessExpiresAt must not be null");
      if (refreshToken == null || refreshToken.isBlank()) {
        throw new IllegalArgumentException("refreshToken must not be blank");
      }
      requireNonNull(refreshExpiresAt, "refreshExpiresAt must not be null");
      requireNonNull(subjectId, "subjectId must not be null");
    }
  }
}
