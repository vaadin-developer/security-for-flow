package eu.jsentinel.jcustos.events.bus;

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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.KeyId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static eu.jsentinel.jcustos.events.bus.ConsumeFailureAction.REJECT;
import static eu.jsentinel.jcustos.events.bus.ConsumeFailureAction.REJECT_AND_DEAD_LETTER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ConsumeFailurePolicy — reject vs dead-letter per failure kind")
class ConsumeFailurePolicyTest {

  private static final List<JSentinelEventVerificationResult> ALL_FAILURES = List.of(
      new JSentinelEventVerificationResult.InvalidSignature("bad"),
      new JSentinelEventVerificationResult.PayloadHashMismatch(EventEnvelopeId.of("e")),
      new JSentinelEventVerificationResult.UnknownKey(KeyId.of("k")),
      new JSentinelEventVerificationResult.KeyRevoked(KeyId.of("k")),
      new JSentinelEventVerificationResult.KeyExpired(KeyId.of("k")),
      new JSentinelEventVerificationResult.Expired(Instant.parse("2026-07-19T10:15:30Z")),
      new JSentinelEventVerificationResult.ReplayDetected(EventEnvelopeId.of("e")),
      new JSentinelEventVerificationResult.SequenceViolation(TenantId.DEFAULT,
          EventProducerId.of("p"), EventSequence.of(2), EventSequence.of(5)),
      new JSentinelEventVerificationResult.ProducerNotAllowed(EventProducerId.of("p"),
          EventType.of("LoginSucceeded"), TenantId.DEFAULT));

  @Test
  @DisplayName("strict() rejects every kind and dead-letters nothing")
  void strictProfile() {
    ConsumeFailurePolicy strict = ConsumeFailurePolicy.strict();
    for (JSentinelEventVerificationResult failure : ALL_FAILURES) {
      assertEquals(REJECT, strict.actionFor(failure), failure.getClass().getSimpleName());
    }
    assertFalse(strict.deadLettersAnything());
  }

  @Test
  @DisplayName("operationalDefaults() dead-letters sequence violations and expired envelopes only")
  void operationalProfile() {
    ConsumeFailurePolicy operational = ConsumeFailurePolicy.operationalDefaults();
    for (JSentinelEventVerificationResult failure : ALL_FAILURES) {
      ConsumeFailureAction expected =
          failure instanceof JSentinelEventVerificationResult.SequenceViolation
              || failure instanceof JSentinelEventVerificationResult.Expired
              ? REJECT_AND_DEAD_LETTER
              : REJECT;
      assertEquals(expected, operational.actionFor(failure),
          failure.getClass().getSimpleName());
    }
    assertTrue(operational.deadLettersAnything());
  }

  @Test
  @DisplayName("custom() starts fail-closed and applies per-kind overrides")
  void customBuilder() {
    ConsumeFailurePolicy custom = ConsumeFailurePolicy.custom()
        .with(ConsumeFailurePolicy.FailureKind.REPLAY_DETECTED, REJECT_AND_DEAD_LETTER)
        .build();
    assertEquals(REJECT_AND_DEAD_LETTER, custom.actionFor(
        new JSentinelEventVerificationResult.ReplayDetected(EventEnvelopeId.of("e"))));
    assertEquals(REJECT, custom.actionFor(
        new JSentinelEventVerificationResult.InvalidSignature("bad")));
  }

  @Test
  @DisplayName("Valid is not a failure")
  void validRejected() {
    ConsumeFailurePolicy policy = ConsumeFailurePolicy.strict();
    assertThrows(IllegalArgumentException.class, () -> policy.actionFor(
        new JSentinelEventVerificationResult.Valid(
            ConsumeFailureFixtures.envelope())));
  }
}
