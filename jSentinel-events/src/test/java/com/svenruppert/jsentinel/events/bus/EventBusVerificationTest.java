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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.keys.InMemoryKeyManagement;
import com.svenruppert.jsentinel.events.producer.AllowListProducerPolicy;
import com.svenruppert.jsentinel.events.sequence.SequenceViolationStrategy;
import com.svenruppert.jsentinel.events.signature.Ed25519SignatureAlgorithm;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithms;
import com.svenruppert.jsentinel.events.api.KeyId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EventBus publish -> consume verification")
class EventBusVerificationTest {

  @Test
  @DisplayName("a freshly published envelope verifies Valid end-to-end")
  void validRoundTrip() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    JSentinelEventVerificationResult result = fx.consumePipeline().verify(env, BusFixtures.T0);
    assertTrue(result.isValid());
    assertInstanceOf(JSentinelEventVerificationResult.Valid.class, result);
  }

  @Test
  @DisplayName("a tampered payload is PayloadHashMismatch")
  void tamperedPayload() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    SignedJSentinelEventEnvelope tampered = BusFixtures.rebuild(env)
        .canonicalPayload("{\"x\":\"y\"}".getBytes(StandardCharsets.UTF_8)).build();
    assertInstanceOf(JSentinelEventVerificationResult.PayloadHashMismatch.class,
        fx.consumePipeline().verify(tampered, BusFixtures.T0));
  }

  @Test
  @DisplayName("a tampered tenantId / eventType / expiresAt all fail the signature")
  void tamperedMetadataFailsSignature() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());

    SignedJSentinelEventEnvelope tenant = BusFixtures.rebuild(env)
        .tenantId(TenantId.of("evil")).build();
    assertInstanceOf(JSentinelEventVerificationResult.InvalidSignature.class,
        fx.consumePipeline().verify(tenant, BusFixtures.T0));

    SignedJSentinelEventEnvelope type = BusFixtures.rebuild(env)
        .eventType(com.svenruppert.jsentinel.events.api.EventType.of("RoleAssigned")).build();
    assertInstanceOf(JSentinelEventVerificationResult.InvalidSignature.class,
        new BusFixtures().consumePipeline().verify(type, BusFixtures.T0));

    SignedJSentinelEventEnvelope expiry = BusFixtures.rebuild(env)
        .expiresAt(BusFixtures.T0.plusSeconds(99999)).build();
    assertInstanceOf(JSentinelEventVerificationResult.InvalidSignature.class,
        new BusFixtures().consumePipeline().verify(expiry, BusFixtures.T0));
  }

  @Test
  @DisplayName("an unknown key is UnknownKey")
  void unknownKey() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    // consumer that knows a different key only
    InMemoryKeyManagement otherKeys =
        new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("other"));
    ConsumePipeline consumer = new ConsumePipeline(otherKeys, SignatureAlgorithms.defaults(),
        fx.consumeReplay, fx.consumeSequence,
        new com.svenruppert.jsentinel.events.sequence.SequenceValidator(),
        SequenceViolationStrategy.REJECT, fx.allowAll);
    assertInstanceOf(JSentinelEventVerificationResult.UnknownKey.class,
        consumer.verify(env, BusFixtures.T0));
  }

  @Test
  @DisplayName("a revoked key is KeyRevoked")
  void revokedKey() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    fx.keyManagement.revoke(BusFixtures.KEY);
    assertInstanceOf(JSentinelEventVerificationResult.KeyRevoked.class,
        fx.consumePipeline().verify(env, BusFixtures.T0));
  }

  @Test
  @DisplayName("an envelope past its window is Expired")
  void expiredEnvelope() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    Instant afterExpiry = BusFixtures.T0.plusSeconds(6 * 60);
    assertInstanceOf(JSentinelEventVerificationResult.Expired.class,
        fx.consumePipeline().verify(env, afterExpiry));
  }

  @Test
  @DisplayName("re-consuming the same envelope is ReplayDetected")
  void replayDetected() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    ConsumePipeline consumer = fx.consumePipeline();
    assertTrue(consumer.verify(env, BusFixtures.T0).isValid());
    assertInstanceOf(JSentinelEventVerificationResult.ReplayDetected.class,
        consumer.verify(env, BusFixtures.T0));
  }

  @Test
  @DisplayName("a sequence gap is a SequenceViolation under REJECT")
  void sequenceViolation() {
    BusFixtures fx = new BusFixtures();
    PublishPipeline publisher = fx.publishPipeline();
    SignedJSentinelEventEnvelope seq1 = publisher.toEnvelope(BusFixtures.event());
    publisher.toEnvelope(BusFixtures.event()); // seq2, not delivered
    SignedJSentinelEventEnvelope seq3 = publisher.toEnvelope(BusFixtures.event());

    ConsumePipeline consumer = fx.consumePipeline();
    assertTrue(consumer.verify(seq1, BusFixtures.T0).isValid());
    JSentinelEventVerificationResult result = consumer.verify(seq3, BusFixtures.T0);
    JSentinelEventVerificationResult.SequenceViolation violation =
        assertInstanceOf(JSentinelEventVerificationResult.SequenceViolation.class, result);
    assertEquals(2, violation.expected().value());
    assertEquals(3, violation.actual().value());
  }

  @Test
  @DisplayName("a producer that may not publish the type is ProducerNotAllowed")
  void producerNotAllowed() {
    BusFixtures fx = new BusFixtures();
    SignedJSentinelEventEnvelope env = fx.publishPipeline().toEnvelope(BusFixtures.event());
    ConsumePipeline strictConsumer = fx.consumePipeline(
        AllowListProducerPolicy.builder().build(), SequenceViolationStrategy.REJECT);
    assertInstanceOf(JSentinelEventVerificationResult.ProducerNotAllowed.class,
        strictConsumer.verify(env, BusFixtures.T0));
  }
}
