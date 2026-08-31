/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.password.audit;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.CredentialRehashed;
import eu.jsentinel.jcustos.audit.CredentialVerificationFailed;
import eu.jsentinel.jcustos.audit.CredentialVerificationSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialAuditPublisherTest {

  /** Real audit service that just records events in memory. */
  private static final class RecordingAuditService implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }
  }

  /** Audit service that always throws. Models a misconfigured sink. */
  private static final class FailingAuditService implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
      throw new RuntimeException("sink unavailable");
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  private static final Clock FIXED_CLOCK = Clock.fixed(
      Instant.parse("2026-06-01T12:34:56Z"), ZoneOffset.UTC);

  @Test
  @DisplayName("Verified result emits a CredentialVerificationSucceeded carrying envelope metadata")
  void verifiedEmitsSuccess() {
    RecordingAuditService sink = new RecordingAuditService();
    CredentialAuditPublisher publisher = new CredentialAuditPublisher(sink, FIXED_CLOCK);

    CredentialVerificationResult result = new CredentialVerificationResult.Verified(
        "encoded-hash",
        CredentialType.PASSWORD,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1, 1, Optional.of("pepper-2026-04"));
    publisher.publish("alice", "10.0.0.1", result,
        RehashDecision.NotRequired.INSTANCE);

    assertEquals(1, sink.events.size());
    CredentialVerificationSucceeded event = assertInstanceOf(
        CredentialVerificationSucceeded.class, sink.events.get(0));
    assertEquals("alice", event.username());
    assertEquals("10.0.0.1", event.clientAddress());
    assertEquals("PBKDF2WithHmacSHA256", event.algorithm());
    assertEquals("pbkdf2-jdk", event.providerId());
    assertEquals(1, event.policyVersion());
    assertTrue(event.pepperKeyIdPresent());
    assertFalse(event.rehashRequired());
    assertEquals(FIXED_CLOCK.instant(), event.timestamp());
  }

  @Test
  @DisplayName("Verified result with Required rehash flags rehashRequired=true")
  void verifiedWithRehashFlagsRehash() {
    RecordingAuditService sink = new RecordingAuditService();
    CredentialAuditPublisher publisher = new CredentialAuditPublisher(sink, FIXED_CLOCK);

    CredentialVerificationResult.Verified result = new CredentialVerificationResult.Verified(
        "encoded-hash",
        CredentialType.PASSWORD,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1, 1, Optional.empty());
    publisher.publish("alice", null, result,
        new RehashDecision.Required(RehashReason.PARAMETERS_OUTDATED, 1));

    CredentialVerificationSucceeded event = (CredentialVerificationSucceeded) sink.events.get(0);
    assertTrue(event.rehashRequired());
    assertFalse(event.pepperKeyIdPresent());
  }

  @Test
  @DisplayName("Failed result emits a CredentialVerificationFailed carrying the internal audit type")
  void failedEmitsFailure() {
    RecordingAuditService sink = new RecordingAuditService();
    CredentialAuditPublisher publisher = new CredentialAuditPublisher(sink, FIXED_CLOCK);

    CredentialVerificationResult result = new CredentialVerificationResult.Failed(
        PublicFailureType.INVALID_CREDENTIALS,
        InternalAuditEventType.VERIFICATION_FAILED_MISMATCH);
    publisher.publish("alice", "10.0.0.1", result,
        RehashDecision.NotRequired.INSTANCE);

    CredentialVerificationFailed event = assertInstanceOf(
        CredentialVerificationFailed.class, sink.events.get(0));
    assertEquals("alice", event.username());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH,
        event.internalAuditEventType());
  }

  @Test
  @DisplayName("publishRehash emits CredentialRehashed with the algorithm transition")
  void rehashEmitted() {
    RecordingAuditService sink = new RecordingAuditService();
    CredentialAuditPublisher publisher = new CredentialAuditPublisher(sink, FIXED_CLOCK);
    publisher.publishRehash("alice",
        "PBKDF2WithHmacSHA256", "Argon2id",
        RehashReason.ALGORITHM_DEPRECATED, 2);

    CredentialRehashed event = assertInstanceOf(
        CredentialRehashed.class, sink.events.get(0));
    assertEquals("alice", event.username());
    assertEquals("PBKDF2WithHmacSHA256", event.fromAlgorithm());
    assertEquals("Argon2id", event.toAlgorithm());
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, event.reason());
    assertEquals(2, event.targetPolicyVersion());
  }

  @Test
  @DisplayName("Audit-sink failure does not propagate to the caller (CWE-778)")
  void sinkFailureDoesNotPropagate() {
    CredentialAuditPublisher publisher = new CredentialAuditPublisher(
        new FailingAuditService(), FIXED_CLOCK);
    // None of the following may throw — that is the entire contract.
    publisher.publish("alice", "10.0.0.1",
        new CredentialVerificationResult.Failed(
            PublicFailureType.INVALID_CREDENTIALS,
            InternalAuditEventType.VERIFICATION_FAILED_MISMATCH),
        RehashDecision.NotRequired.INSTANCE);
    publisher.publish("alice", null,
        new CredentialVerificationResult.Verified(
            "encoded-hash", CredentialType.PASSWORD,
            "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1, 1, Optional.empty()),
        new RehashDecision.Required(RehashReason.POLICY_VERSION_OUTDATED, 1));
    publisher.publishRehash("alice",
        "PBKDF2WithHmacSHA256", "Argon2id",
        RehashReason.ALGORITHM_DEPRECATED, 2);
  }

  @Test
  @DisplayName("Failed event with TEMPORARILY_UNAVAILABLE still carries the internal classification")
  void temporarilyUnavailableMappedThrough() {
    RecordingAuditService sink = new RecordingAuditService();
    CredentialAuditPublisher publisher = new CredentialAuditPublisher(sink, FIXED_CLOCK);
    publisher.publish("alice", null,
        new CredentialVerificationResult.Failed(
            PublicFailureType.TEMPORARILY_UNAVAILABLE,
            InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT),
        RehashDecision.NotRequired.INSTANCE);
    CredentialVerificationFailed event = (CredentialVerificationFailed) sink.events.get(0);
    assertEquals(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT,
        event.internalAuditEventType());
  }
}
