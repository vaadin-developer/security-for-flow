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

import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@DisplayName("SelfObservabilityEvents")
class SelfObservabilityEventsTest {

  private static final Instant NOW = Instant.parse("2026-07-19T12:00:00Z");

  /** One real signed envelope through the real pipeline — no mocks. */
  private static final SignedJCustosEventEnvelope ENVELOPE =
      new BusFixtures().publishPipeline().toEnvelope(BusFixtures.event());

  @Test
  @DisplayName("Valid maps to no event at all")
  void validMapsToEmpty() {
    Optional<EventBusSelfObservabilityEvent> mapped = SelfObservabilityEvents.fromVerification(
        new JCustosEventVerificationResult.Valid(ENVELOPE), ENVELOPE, NOW);
    assertTrue(mapped.isEmpty());
  }

  @Test
  @DisplayName("the REASON_* constants are pinned literally")
  void reasonConstantsArePinned() {
    assertEquals("unknown-key", SelfObservabilityEvents.REASON_UNKNOWN_KEY);
    assertEquals("key-revoked", SelfObservabilityEvents.REASON_KEY_REVOKED);
    assertEquals("key-expired", SelfObservabilityEvents.REASON_KEY_EXPIRED);
    assertEquals("expired", SelfObservabilityEvents.REASON_EXPIRED);
    assertEquals("producer-not-allowed", SelfObservabilityEvents.REASON_PRODUCER_NOT_ALLOWED);
  }

  static Stream<Arguments> failureCases() {
    return Stream.of(
        arguments("InvalidSignature",
            new JCustosEventVerificationResult.InvalidSignature("signature does not verify"),
            SignatureInvalidEvent.class, JCustosEventSeverity.ERROR),
        arguments("PayloadHashMismatch",
            new JCustosEventVerificationResult.PayloadHashMismatch(ENVELOPE.envelopeId()),
            SignatureInvalidEvent.class, JCustosEventSeverity.ERROR),
        arguments("ReplayDetected",
            new JCustosEventVerificationResult.ReplayDetected(ENVELOPE.envelopeId()),
            ReplayDetectedEvent.class, JCustosEventSeverity.CRITICAL),
        arguments("SequenceViolation",
            new JCustosEventVerificationResult.SequenceViolation(ENVELOPE.tenantId(),
                ENVELOPE.producerId(), EventSequence.of(4), EventSequence.of(2)),
            SequenceViolationEvent.class, JCustosEventSeverity.ERROR),
        arguments("UnknownKey",
            new JCustosEventVerificationResult.UnknownKey(ENVELOPE.keyId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("KeyRevoked",
            new JCustosEventVerificationResult.KeyRevoked(ENVELOPE.keyId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("KeyExpired",
            new JCustosEventVerificationResult.KeyExpired(ENVELOPE.keyId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("Expired",
            new JCustosEventVerificationResult.Expired(ENVELOPE.expiresAt()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("ProducerNotAllowed",
            new JCustosEventVerificationResult.ProducerNotAllowed(ENVELOPE.producerId(),
                ENVELOPE.eventType(), ENVELOPE.tenantId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("failureCases")
  @DisplayName("every failure maps to exactly one event of the most specific type")
  void everyFailureMapsToExactlyOneEvent(String name,
      JCustosEventVerificationResult result,
      Class<? extends EventBusSelfObservabilityEvent> expectedType,
      JCustosEventSeverity expectedSeverity) {
    Optional<EventBusSelfObservabilityEvent> mapped =
        SelfObservabilityEvents.fromVerification(result, ENVELOPE, NOW);
    // Optional<EventBusSelfObservabilityEvent> IS the exactly-one contract:
    // a failure never yields zero events and can never yield two.
    assertTrue(mapped.isPresent(), name + " must map to an event");
    EventBusSelfObservabilityEvent event = mapped.get();
    assertInstanceOf(expectedType, event);
    assertEquals(expectedSeverity, event.severity());
    assertEquals(ENVELOPE.tenantId(), event.tenantId(), "tenant propagated from envelope");
    assertEquals(JCustosEvent.SYSTEM_SUBJECT, event.subjectId());
    assertEquals(NOW, event.occurredAt());
  }

  static Stream<Arguments> rejectionReasonCases() {
    return Stream.of(
        arguments("UnknownKey",
            new JCustosEventVerificationResult.UnknownKey(ENVELOPE.keyId()), "unknown-key"),
        arguments("KeyRevoked",
            new JCustosEventVerificationResult.KeyRevoked(ENVELOPE.keyId()), "key-revoked"),
        arguments("KeyExpired",
            new JCustosEventVerificationResult.KeyExpired(ENVELOPE.keyId()), "key-expired"),
        arguments("Expired",
            new JCustosEventVerificationResult.Expired(ENVELOPE.expiresAt()), "expired"),
        arguments("ProducerNotAllowed",
            new JCustosEventVerificationResult.ProducerNotAllowed(ENVELOPE.producerId(),
                ENVELOPE.eventType(), ENVELOPE.tenantId()), "producer-not-allowed"));
  }

  @ParameterizedTest(name = "{0} -> {2}")
  @MethodSource("rejectionReasonCases")
  @DisplayName("the rejection family carries the literal reason and the envelope id")
  void rejectionFamilyCarriesReasonAndEnvelopeId(String name,
      JCustosEventVerificationResult result, String expectedReason) {
    EnvelopeRejectedEvent event = (EnvelopeRejectedEvent) SelfObservabilityEvents
        .fromVerification(result, ENVELOPE, NOW).orElseThrow();
    assertEquals(expectedReason, event.reason());
    assertEquals(ENVELOPE.envelopeId().value(), event.rejectedEnvelopeId());
  }

  @Test
  @DisplayName("InvalidSignature and PayloadHashMismatch both carry the envelope id")
  void signatureFamilyCarriesEnvelopeId() {
    SignatureInvalidEvent fromSignature = (SignatureInvalidEvent) SelfObservabilityEvents
        .fromVerification(new JCustosEventVerificationResult.InvalidSignature("bad"),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals(ENVELOPE.envelopeId().value(), fromSignature.envelopeId());

    SignatureInvalidEvent fromHash = (SignatureInvalidEvent) SelfObservabilityEvents
        .fromVerification(
            new JCustosEventVerificationResult.PayloadHashMismatch(ENVELOPE.envelopeId()),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals(ENVELOPE.envelopeId().value(), fromHash.envelopeId());
  }

  @Test
  @DisplayName("ReplayDetected carries the replayed envelope id")
  void replayCarriesEnvelopeId() {
    ReplayDetectedEvent event = (ReplayDetectedEvent) SelfObservabilityEvents
        .fromVerification(
            new JCustosEventVerificationResult.ReplayDetected(ENVELOPE.envelopeId()),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals(ENVELOPE.envelopeId().value(), event.replayedEnvelopeId());
  }

  @Test
  @DisplayName("SequenceViolation maps producer, expected and actual")
  void sequenceViolationMapsComponents() {
    SequenceViolationEvent event = (SequenceViolationEvent) SelfObservabilityEvents
        .fromVerification(
            new JCustosEventVerificationResult.SequenceViolation(ENVELOPE.tenantId(),
                ENVELOPE.producerId(), EventSequence.of(4), EventSequence.of(2)),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals(ENVELOPE.producerId().value(), event.producerId());
    assertEquals(4, event.expected());
    assertEquals(2, event.actual());
  }
}
