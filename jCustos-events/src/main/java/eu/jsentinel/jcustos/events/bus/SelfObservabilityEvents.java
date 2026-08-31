package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Maps a {@link JCustosEventVerificationResult} to the self-observability
 * event describing it.
 *
 * <p>Mapping contract: every failure result maps to <em>exactly one</em>
 * event — the most specific one — never two. The monitoring bridge builds the
 * {@code security.eventbus.rejected.total} umbrella metric from the whole
 * rejection event family, so a double-publish here would double-count.
 * <ul>
 *   <li>{@link JCustosEventVerificationResult.InvalidSignature} and
 *       {@link JCustosEventVerificationResult.PayloadHashMismatch} both map
 *       to {@link SignatureInvalidEvent}: the canonical payload is bound to
 *       the signed metadata through its hash, so a hash mismatch is a failure
 *       of the same cryptographic content binding as an invalid signature
 *       (see {@link SignatureInvalidEvent}).</li>
 *   <li>{@link JCustosEventVerificationResult.ReplayDetected} maps to
 *       {@link ReplayDetectedEvent}.</li>
 *   <li>{@link JCustosEventVerificationResult.SequenceViolation} maps to
 *       {@link SequenceViolationEvent}.</li>
 *   <li>Every remaining failure (unknown / revoked / expired key, expired
 *       envelope, producer not allowed) maps to
 *       {@link EnvelopeRejectedEvent} with one of the {@code REASON_*}
 *       constants.</li>
 * </ul>
 *
 * <p>Severity: every failure carries {@link JCustosEventSeverity#ERROR},
 * except a detected replay which carries
 * {@link JCustosEventSeverity#CRITICAL} — the Konzept mandates "erkannter
 * Replay fuehrt zu Reject und kritischem Security Event" and the severity
 * enum expresses that level directly. The metadata tenant comes from the
 * envelope, the subject is {@link JCustosEvent#SYSTEM_SUBJECT} and the
 * timestamp is the caller-supplied {@code now}.
 *
 * <p>Publish-side note: the pipeline rejects a publish <em>before</em> an
 * envelope exists, so on that path (see {@code DefaultJCustosEventBus})
 * the event id doubles as the {@code rejectedEnvelopeId} of the emitted
 * {@link EnvelopeRejectedEvent}.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class SelfObservabilityEvents {

  /** Rejection reason: the referenced key id is unknown. */
  public static final String REASON_UNKNOWN_KEY = "unknown-key";

  /** Rejection reason: the referenced key has been revoked. */
  public static final String REASON_KEY_REVOKED = "key-revoked";

  /** Rejection reason: the referenced key is past its validity window. */
  public static final String REASON_KEY_EXPIRED = "key-expired";

  /** Rejection reason: the envelope is past its acceptance window. */
  public static final String REASON_EXPIRED = "expired";

  /** Rejection reason: the producer may not publish this event type. */
  public static final String REASON_PRODUCER_NOT_ALLOWED = "producer-not-allowed";

  private SelfObservabilityEvents() {
  }

  /**
   * Maps a verification result to its self-observability event.
   *
   * @param result the verification outcome
   * @param envelope the envelope the result is about (supplies tenant and,
   *     where the result carries no id of its own, the envelope id)
   * @param now the emission timestamp
   * @return the single most specific event, or empty for
   *     {@link JCustosEventVerificationResult.Valid}
   */
  public static Optional<EventBusSelfObservabilityEvent> fromVerification(
      JCustosEventVerificationResult result, SignedJCustosEventEnvelope envelope,
      Instant now) {
    Objects.requireNonNull(result, "result");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(now, "now");
    return switch (result) {
      case JCustosEventVerificationResult.Valid ignored -> Optional.empty();
      case JCustosEventVerificationResult.InvalidSignature ignored ->
          Optional.of(new SignatureInvalidEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR),
              envelope.envelopeId().value()));
      case JCustosEventVerificationResult.PayloadHashMismatch mismatch ->
          Optional.of(new SignatureInvalidEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR),
              mismatch.envelopeId().value()));
      case JCustosEventVerificationResult.ReplayDetected replay ->
          Optional.of(new ReplayDetectedEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.CRITICAL),
              replay.envelopeId().value()));
      case JCustosEventVerificationResult.SequenceViolation violation ->
          Optional.of(new SequenceViolationEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR),
              violation.producerId().value(),
              violation.expected().value(),
              violation.actual().value()));
      case JCustosEventVerificationResult.UnknownKey ignored ->
          rejected(envelope, now, REASON_UNKNOWN_KEY);
      case JCustosEventVerificationResult.KeyRevoked ignored ->
          rejected(envelope, now, REASON_KEY_REVOKED);
      case JCustosEventVerificationResult.KeyExpired ignored ->
          rejected(envelope, now, REASON_KEY_EXPIRED);
      case JCustosEventVerificationResult.Expired ignored ->
          rejected(envelope, now, REASON_EXPIRED);
      case JCustosEventVerificationResult.ProducerNotAllowed ignored ->
          rejected(envelope, now, REASON_PRODUCER_NOT_ALLOWED);
    };
  }

  private static Optional<EventBusSelfObservabilityEvent> rejected(
      SignedJCustosEventEnvelope envelope, Instant now, String reason) {
    return Optional.of(new EnvelopeRejectedEvent(
        failureMetadata(envelope, now, JCustosEventSeverity.ERROR),
        envelope.envelopeId().value(), reason));
  }

  private static EventMetadata failureMetadata(SignedJCustosEventEnvelope envelope,
      Instant now, JCustosEventSeverity severity) {
    return EventMetadata.create(envelope.tenantId(), JCustosEvent.SYSTEM_SUBJECT,
        now, severity);
  }
}
