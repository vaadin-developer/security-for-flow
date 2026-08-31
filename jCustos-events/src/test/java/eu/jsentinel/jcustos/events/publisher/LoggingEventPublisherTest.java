package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Marker;
import org.slf4j.event.Level;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoggingEventPublisher")
class LoggingEventPublisherTest {

  @Test
  @DisplayName("writes the stable one-line EVENT format (golden line)")
  void goldenLine() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingEventPublisher(logger).onEnvelope(PublisherFixtures.validBuilder().build());

    assertEquals("EVENT envelope=env-1 type=LoginSucceeded tenant=default subject=alice "
            + "producer=rest-service-primary seq=7 occurredAt=2026-06-24T10:15:30Z "
            + "correlation=corr-1 causation=cause-1 key=key-1 alg=Ed25519 payloadHash=abc123",
        logger.firstMessage());
  }

  @Test
  @DisplayName("an absent causationId is rendered as '-'")
  void absentCausationRenderedAsDash() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingEventPublisher(logger)
        .onEnvelope(PublisherFixtures.validBuilder().causationId(null).build());

    assertTrue(logger.firstMessage().contains(" causation=- "),
        "expected 'causation=-' in: " + logger.firstMessage());
  }

  @Test
  @DisplayName("the line never carries payload or signature content")
  void noPayloadOrSignatureContent() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingEventPublisher(logger).onEnvelope(PublisherFixtures.validBuilder().build());

    String line = logger.firstMessage();
    assertFalse(line.contains("TOPSECRET"), "payload content leaked into: " + line);
    assertFalse(line.contains("signature="), "signature field leaked into: " + line);
  }

  @Test
  @DisplayName("CWE-117: a hostile envelope id is scrubbed before logging")
  void hostileEnvelopeIdIsScrubbed() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    SignedJCustosEventEnvelope hostile = PublisherFixtures.validBuilder()
        .envelopeId(EventEnvelopeId.of("env\nEVENT forged=line"))
        .build();
    new LoggingEventPublisher(logger).onEnvelope(hostile);

    String line = logger.firstMessage();
    assertTrue(line.contains("envelope=env?EVENT?forged=line"),
        "expected scrubbed envelope id in: " + line);
    assertFalse(line.contains("\n"), "raw newline leaked into: " + line);
  }

  @Test
  @DisplayName("never throws — a throwing logger is swallowed (R036)")
  void neverThrows() {
    RecordingSlf4jLogger throwing = new RecordingSlf4jLogger() {
      @Override
      protected void handleNormalizedLoggingCall(Level level, Marker marker,
          String messagePattern, Object[] arguments, Throwable throwable) {
        throw new IllegalStateException("logger boom");
      }
    };
    LoggingEventPublisher publisher = new LoggingEventPublisher(throwing);
    assertDoesNotThrow(() -> publisher.onEnvelope(PublisherFixtures.validBuilder().build()));
    assertDoesNotThrow(() -> publisher.onEnvelope(null));
  }
}
