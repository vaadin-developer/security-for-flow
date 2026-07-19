package com.svenruppert.jsentinel.events.bus;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.types.EnvelopeRejectedEvent;
import com.svenruppert.jsentinel.events.types.EventBusSelfObservabilityEvent;
import com.svenruppert.jsentinel.events.types.ReplayDetectedEvent;
import com.svenruppert.jsentinel.events.types.SequenceViolationEvent;
import com.svenruppert.jsentinel.events.types.SignatureInvalidEvent;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Maps a {@link JSentinelEventVerificationResult} to the self-observability
 * event describing it.
 *
 * <p>Mapping contract: every failure result maps to <em>exactly one</em>
 * event — the most specific one — never two. The monitoring bridge builds the
 * {@code security.eventbus.rejected.total} umbrella metric from the whole
 * rejection event family, so a double-publish here would double-count.
 * <ul>
 *   <li>{@link JSentinelEventVerificationResult.InvalidSignature} and
 *       {@link JSentinelEventVerificationResult.PayloadHashMismatch} both map
 *       to {@link SignatureInvalidEvent}: the canonical payload is bound to
 *       the signed metadata through its hash, so a hash mismatch is a failure
 *       of the same cryptographic content binding as an invalid signature
 *       (see {@link SignatureInvalidEvent}).</li>
 *   <li>{@link JSentinelEventVerificationResult.ReplayDetected} maps to
 *       {@link ReplayDetectedEvent}.</li>
 *   <li>{@link JSentinelEventVerificationResult.SequenceViolation} maps to
 *       {@link SequenceViolationEvent}.</li>
 *   <li>Every remaining failure (unknown / revoked / expired key, expired
 *       envelope, producer not allowed) maps to
 *       {@link EnvelopeRejectedEvent} with one of the {@code REASON_*}
 *       constants.</li>
 * </ul>
 *
 * <p>Severity: every failure carries {@link JSentinelEventSeverity#ERROR},
 * except a detected replay which carries
 * {@link JSentinelEventSeverity#CRITICAL} — the Konzept mandates "erkannter
 * Replay fuehrt zu Reject und kritischem Security Event" and the severity
 * enum expresses that level directly. The metadata tenant comes from the
 * envelope, the subject is {@link JSentinelEvent#SYSTEM_SUBJECT} and the
 * timestamp is the caller-supplied {@code now}.
 *
 * <p>Publish-side note: the pipeline rejects a publish <em>before</em> an
 * envelope exists, so on that path (see {@code DefaultJSentinelEventBus})
 * the event id doubles as the {@code rejectedEnvelopeId} of the emitted
 * {@link EnvelopeRejectedEvent}.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
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
   *     {@link JSentinelEventVerificationResult.Valid}
   */
  public static Optional<EventBusSelfObservabilityEvent> fromVerification(
      JSentinelEventVerificationResult result, SignedJSentinelEventEnvelope envelope,
      Instant now) {
    Objects.requireNonNull(result, "result");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(now, "now");
    return switch (result) {
      case JSentinelEventVerificationResult.Valid ignored -> Optional.empty();
      case JSentinelEventVerificationResult.InvalidSignature ignored ->
          Optional.of(new SignatureInvalidEvent(
              failureMetadata(envelope, now, JSentinelEventSeverity.ERROR),
              envelope.envelopeId().value()));
      case JSentinelEventVerificationResult.PayloadHashMismatch mismatch ->
          Optional.of(new SignatureInvalidEvent(
              failureMetadata(envelope, now, JSentinelEventSeverity.ERROR),
              mismatch.envelopeId().value()));
      case JSentinelEventVerificationResult.ReplayDetected replay ->
          Optional.of(new ReplayDetectedEvent(
              failureMetadata(envelope, now, JSentinelEventSeverity.CRITICAL),
              replay.envelopeId().value()));
      case JSentinelEventVerificationResult.SequenceViolation violation ->
          Optional.of(new SequenceViolationEvent(
              failureMetadata(envelope, now, JSentinelEventSeverity.ERROR),
              violation.producerId().value(),
              violation.expected().value(),
              violation.actual().value()));
      case JSentinelEventVerificationResult.UnknownKey ignored ->
          rejected(envelope, now, REASON_UNKNOWN_KEY);
      case JSentinelEventVerificationResult.KeyRevoked ignored ->
          rejected(envelope, now, REASON_KEY_REVOKED);
      case JSentinelEventVerificationResult.KeyExpired ignored ->
          rejected(envelope, now, REASON_KEY_EXPIRED);
      case JSentinelEventVerificationResult.Expired ignored ->
          rejected(envelope, now, REASON_EXPIRED);
      case JSentinelEventVerificationResult.ProducerNotAllowed ignored ->
          rejected(envelope, now, REASON_PRODUCER_NOT_ALLOWED);
    };
  }

  private static Optional<EventBusSelfObservabilityEvent> rejected(
      SignedJSentinelEventEnvelope envelope, Instant now, String reason) {
    return Optional.of(new EnvelopeRejectedEvent(
        failureMetadata(envelope, now, JSentinelEventSeverity.ERROR),
        envelope.envelopeId().value(), reason));
  }

  private static EventMetadata failureMetadata(SignedJSentinelEventEnvelope envelope,
      Instant now, JSentinelEventSeverity severity) {
    return EventMetadata.create(envelope.tenantId(), JSentinelEvent.SYSTEM_SUBJECT,
        now, severity);
  }
}
