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

import com.svenruppert.vaadin.security.audit.EmailVerificationRequested;
import com.svenruppert.vaadin.security.audit.EmailVerified;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authentication.PasswordHasher;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * Email-verification workflow over an
 * {@link EmailVerificationTokenStore}.
 * <p>
 * Mirrors {@link PasswordResetService} but carries the verified
 * email address on the record (a password-reset record has no such
 * field). Three-step lifecycle:
 * <ol>
 *   <li>{@link #request(SubjectId, String, Duration) request(subject, email, ttl)}
 *       — generates a plain token, persists only its hash with
 *       the email it confirms, emits
 *       {@link EmailVerificationRequested}, hands the plain token
 *       to the {@link SecurityNotificationSender}.</li>
 *   <li>{@link #validate(String) validate(plain)} — looks the
 *       token up; returns the record only when live, in this
 *       tenant, not consumed, not expired.</li>
 *   <li>{@link #consume(String) consume(plain)} — marks the token
 *       consumed exactly once and emits {@link EmailVerified}.</li>
 * </ol>
 *
 * <p>Bound to one {@link TenantId} at construction.
 */
@ExperimentalSecurityApi
public final class EmailVerificationService {

  /** Default token entropy in bytes (256 bits). */
  public static final int DEFAULT_TOKEN_BYTES = 32;

  private final EmailVerificationTokenStore store;
  private final PasswordHasher hasher;
  private final SecurityAuditService auditService;
  private final SecurityNotificationSender notificationSender;
  private final TenantId tenant;
  private final Clock clock;
  private final Supplier<String> tokenSource;

  /**
   * Convenience constructor: tenant {@link TenantId#DEFAULT},
   * system clock, 256-bit token source.
   *
   * @param store              backing token store; non-null
   * @param hasher             password hasher used to hash tokens; non-null
   * @param auditService       audit sink; non-null
   * @param notificationSender notification dispatcher; non-null
   */
  public EmailVerificationService(EmailVerificationTokenStore store,
                                  PasswordHasher hasher,
                                  SecurityAuditService auditService,
                                  SecurityNotificationSender notificationSender) {
    this(store, hasher, auditService, notificationSender,
        TenantId.DEFAULT, Clock.systemUTC(), defaultTokenSource());
  }

  /**
   * Full constructor.
   *
   * @param store              backing token store; non-null
   * @param hasher             password hasher used to hash tokens; non-null
   * @param auditService       audit sink; non-null
   * @param notificationSender notification dispatcher; non-null
   * @param tenant             tenant scope; {@code null} becomes
   *                           {@link TenantId#DEFAULT}
   * @param clock              time source; non-null
   * @param tokenSource        plain-token supplier; non-null, non-blank
   */
  public EmailVerificationService(EmailVerificationTokenStore store,
                                  PasswordHasher hasher,
                                  SecurityAuditService auditService,
                                  SecurityNotificationSender notificationSender,
                                  TenantId tenant,
                                  Clock clock,
                                  Supplier<String> tokenSource) {
    this.store = requireNonNull(store, "store must not be null");
    this.hasher = requireNonNull(hasher, "hasher must not be null");
    this.auditService = requireNonNull(auditService, "auditService must not be null");
    this.notificationSender = requireNonNull(notificationSender,
        "notificationSender must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.tokenSource = requireNonNull(tokenSource, "tokenSource must not be null");
  }

  /**
   * Issues a verification token for {@code subjectId} / {@code email}.
   *
   * @param subjectId subject whose email is being verified; non-null
   * @param email     email address being verified; non-blank
   * @param ttl       token lifetime; strictly positive
   * @return issued token (plain value + persisted record)
   */
  public IssuedToken request(SubjectId subjectId, String email, Duration ttl) {
    requireNonNull(subjectId, "subjectId must not be null");
    if (email == null || email.isBlank()) {
      throw new IllegalArgumentException("email must not be blank");
    }
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
    EmailVerificationTokenRecord record = new EmailVerificationTokenRecord(
        hash, tenant, subjectId, email, now, now.plus(ttl), Optional.empty());
    store.save(record);
    publishRequested(now, subjectId, email, hash);
    notify(SecurityNotification.Kind.EMAIL_VERIFICATION_REQUESTED,
        subjectId, now,
        Map.of(
            "tokenPlain", plain,
            "email", email,
            "expiresAt", record.expiresAt().toString()));
    return new IssuedToken(plain, record);
  }

  /**
   * Validates a candidate plain token. Live records only.
   *
   * @param plainToken plain token; null/blank yields empty
   * @return matching live record, if any
   */
  public Optional<EmailVerificationTokenRecord> validate(String plainToken) {
    if (plainToken == null || plainToken.isBlank()) {
      return Optional.empty();
    }
    String hash = hasher.hash(plainToken.toCharArray());
    Optional<EmailVerificationTokenRecord> match = store.findByHash(hash);
    if (match.isEmpty()) {
      return Optional.empty();
    }
    EmailVerificationTokenRecord record = match.get();
    if (!record.tenant().equals(tenant)) {
      return Optional.empty();
    }
    if (record.isConsumed()) {
      return Optional.empty();
    }
    if (record.isExpired(clock.instant())) {
      return Optional.empty();
    }
    return Optional.of(record);
  }

  /**
   * Marks the token consumed exactly once, emits {@link EmailVerified}
   * and a {@link SecurityNotification.Kind#EMAIL_VERIFIED}
   * notification.
   *
   * @param plainToken plain token; null/blank yields empty
   * @return consumed record on the successful transition, empty
   *         otherwise
   */
  public Optional<EmailVerificationTokenRecord> consume(String plainToken) {
    Optional<EmailVerificationTokenRecord> validated = validate(plainToken);
    if (validated.isEmpty()) {
      return Optional.empty();
    }
    EmailVerificationTokenRecord record = validated.get();
    Instant now = clock.instant();
    if (!store.markConsumed(record.tokenHash(), now)) {
      return Optional.empty();
    }
    publishVerified(now, record.subjectId(), record.email(), record.tokenHash());
    notify(SecurityNotification.Kind.EMAIL_VERIFIED,
        record.subjectId(), now,
        Map.of("email", record.email()));
    return Optional.of(record.withConsumedAt(now));
  }

  /**
   * Drops every token issued to {@code subjectId} in this service's
   * tenant.
   *
   * @param subjectId subject; non-null
   * @return number of tokens removed
   */
  public int revokeAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    return store.deleteBySubject(tenant, subjectId);
  }

  /**
   * Purges every expired record in the backing store. Spans all
   * tenants.
   *
   * @return number of records purged
   */
  public int purgeExpired() {
    return store.purgeExpired(clock.instant());
  }

  private void publishRequested(Instant at, SubjectId subjectId, String email, String hash) {
    try {
      auditService.publish(new EmailVerificationRequested(at, subjectId.value(), email, hash));
    } catch (RuntimeException ignored) {
      // sinks must not block the flow
    }
  }

  private void publishVerified(Instant at, SubjectId subjectId, String email, String hash) {
    try {
      auditService.publish(new EmailVerified(at, subjectId.value(), email, hash));
    } catch (RuntimeException ignored) {
      // sinks must not block the flow
    }
  }

  private void notify(SecurityNotification.Kind kind,
                      SubjectId subjectId,
                      Instant at,
                      Map<String, String> attributes) {
    try {
      notificationSender.send(new SecurityNotification(
          kind, subjectId, tenant, at, attributes));
    } catch (RuntimeException ignored) {
      // senders must not block the flow
    }
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
   * Tuple returned from {@link #request request}: the plain token
   * (caller forwards it via the notification sender) and the
   * persisted record (handy for tests / audit hooks).
   *
   * @param plainToken plain token value
   * @param record     persisted record (hash + metadata)
   */
  public record IssuedToken(String plainToken, EmailVerificationTokenRecord record) {
    /** Validates the components. */
    public IssuedToken {
      if (plainToken == null || plainToken.isBlank()) {
        throw new IllegalArgumentException("plainToken must not be blank");
      }
      requireNonNull(record, "record must not be null");
    }
  }
}
