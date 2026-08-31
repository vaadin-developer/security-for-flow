package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link SignedEnvelopePublisher} implementations,
 * pinning the tap's behavioral obligations: the bus delivers on the publish
 * thread, so an implementation must accept envelopes without throwing, must
 * tolerate re-delivery, must be fast or hand off internally, and must survive
 * hostile payload bytes (a publisher never interprets the payload).
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
@DisplayName("SignedEnvelopePublisher — contract")
public interface EnvelopePublisherContract {

  /** Envelope count of the burst case. */
  int BURST_SIZE = 100;

  /**
   * Generous wall-clock bound for the burst case — the tap runs on the
   * publish thread, so it must be fast or hand off, never block.
   */
  Duration MAX_BURST_DURATION = Duration.ofSeconds(5);

  SignedEnvelopePublisher publisherUnderTest();

  @Test
  @DisplayName("accepts a valid envelope without throwing")
  default void acceptsEnvelope() {
    SignedEnvelopePublisher publisher = publisherUnderTest();
    assertDoesNotThrow(() -> publisher.onEnvelope(TestkitEnvelopes.envelope("env-1")));
  }

  @Test
  @DisplayName("tolerates repeated delivery of the same envelope")
  default void toleratesRepeatedDelivery() {
    SignedEnvelopePublisher publisher = publisherUnderTest();
    SignedJCustosEventEnvelope envelope = TestkitEnvelopes.envelope("env-1");
    assertDoesNotThrow(() -> {
      publisher.onEnvelope(envelope);
      publisher.onEnvelope(envelope);
    });
  }

  @Test
  @DisplayName("handles a burst of envelopes quickly — fast or hand-off, never blocking")
  default void handlesBurstQuickly() {
    SignedEnvelopePublisher publisher = publisherUnderTest();
    long start = System.nanoTime();
    for (int i = 0; i < BURST_SIZE; i++) {
      publisher.onEnvelope(TestkitEnvelopes.envelope("env-" + i));
    }
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
    assertTrue(elapsed.compareTo(MAX_BURST_DURATION) < 0,
        "delivering " + BURST_SIZE + " envelopes took " + elapsed
            + " — a publisher on the publish thread must not block");
  }

  @Test
  @DisplayName("tolerates a payload containing raw newline bytes")
  default void toleratesNewlinePayload() {
    SignedEnvelopePublisher publisher = publisherUnderTest();
    byte[] payload = "line1\nline2\r\nEVENT forged=line"
        .getBytes(StandardCharsets.UTF_8);
    assertDoesNotThrow(
        () -> publisher.onEnvelope(TestkitEnvelopes.envelope("env-newline", payload)));
  }
}
