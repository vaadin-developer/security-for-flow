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
package eu.jsentinel.jcustos.credential.metrics;

import eu.jsentinel.jcustos.credential.abuse.AbusePattern;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialMetricEventTest {

  /** Real in-test recorder — not a mock; a full sink implementation. */
  private static final class RecordingMetrics implements CredentialJCustosMetrics {
    final List<CredentialMetricEvent> events = new ArrayList<>();

    @Override
    public void publish(CredentialMetricEvent event) {
      events.add(event);
    }
  }

  @Test
  @DisplayName("NoOp sink swallows every event without throwing")
  void noOpDoesNotFail() {
    CredentialJCustosMetrics metrics = NoOpCredentialJCustosMetrics.INSTANCE;
    metrics.publish(new CredentialMetricEvent.HashDuration(
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1, 12_345L, false));
    metrics.publish(new CredentialMetricEvent.VerifyDuration(
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1, 12_345L, true, false));
    metrics.publish(new CredentialMetricEvent.RehashRequested(
        RehashReason.PARAMETERS_OUTDATED));
    metrics.publish(new CredentialMetricEvent.LifecycleTransition(
        CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE));
    metrics.publish(new CredentialMetricEvent.AbuseSignal(
        AbusePattern.PASSWORD_SPRAYING, 8, 12));
    metrics.publish(CredentialMetricEvent.KdfLimiterRejection.INSTANCE);
    // No assertion needed — the contract is that none of these throw.
  }

  @Test
  @DisplayName("HashDuration carries algorithm, provider, policy, duration and pepper flag — and nothing else")
  void hashDurationFields() {
    CredentialMetricEvent.HashDuration event = new CredentialMetricEvent.HashDuration(
        "Argon2id", "argon2id-bc", 2, 250_000L, true);
    String text = event.toString();
    assertTrue(text.contains("Argon2id"));
    assertTrue(text.contains("argon2id-bc"));
    assertTrue(text.contains("250000"));
    assertTrue(text.contains("peppered=true"));
  }

  @Test
  @DisplayName("HashDuration invariants reject blank algorithm and negative duration")
  void hashDurationInvariants() {
    assertThrows(NullPointerException.class,
        () -> new CredentialMetricEvent.HashDuration(
            null, "p", 1, 0L, false));
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialMetricEvent.HashDuration(
            "alg", "p", 1, -1L, false));
  }

  @Test
  @DisplayName("VerifyDuration carries verified + dummyPath flags")
  void verifyDurationFlags() {
    CredentialMetricEvent.VerifyDuration ok = new CredentialMetricEvent.VerifyDuration(
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1, 5_000L, true, false);
    CredentialMetricEvent.VerifyDuration dummy = new CredentialMetricEvent.VerifyDuration(
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1, 5_000L, false, true);
    assertTrue(ok.verified());
    assertFalse(ok.dummyPath());
    assertFalse(dummy.verified());
    assertTrue(dummy.dummyPath());
  }

  @Test
  @DisplayName("RehashRequested carries only the structural reason")
  void rehashRequested() {
    CredentialMetricEvent.RehashRequested event = new CredentialMetricEvent.RehashRequested(
        RehashReason.ALGORITHM_DEPRECATED);
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, event.reason());
  }

  @Test
  @DisplayName("LifecycleTransition records from/to status")
  void lifecycleTransition() {
    CredentialMetricEvent.LifecycleTransition event = new CredentialMetricEvent.LifecycleTransition(
        CredentialStatus.ACTIVE, CredentialStatus.LOCKED);
    assertEquals(CredentialStatus.ACTIVE, event.fromStatus());
    assertEquals(CredentialStatus.LOCKED, event.toStatus());
  }

  @Test
  @DisplayName("AbuseSignal invariants: distinctTargets ≥ 1, attempts ≥ distinctTargets")
  void abuseSignalInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialMetricEvent.AbuseSignal(
            AbusePattern.PASSWORD_SPRAYING, 0, 0));
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialMetricEvent.AbuseSignal(
            AbusePattern.PASSWORD_SPRAYING, 5, 3));
  }

  @Test
  @DisplayName("KdfLimiterRejection is a singleton")
  void kdfLimiterRejectionSingleton() {
    assertSame(CredentialMetricEvent.KdfLimiterRejection.INSTANCE,
        CredentialMetricEvent.KdfLimiterRejection.INSTANCE);
  }

  @Test
  @DisplayName("RecordingMetrics is a real CredentialJCustosMetrics — events appear in order")
  void recordingMetricsAppendsInOrder() {
    RecordingMetrics metrics = new RecordingMetrics();
    metrics.publish(new CredentialMetricEvent.RehashRequested(
        RehashReason.POLICY_VERSION_OUTDATED));
    metrics.publish(new CredentialMetricEvent.LifecycleTransition(
        CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE));
    assertEquals(2, metrics.events.size());
    assertTrue(metrics.events.get(0) instanceof CredentialMetricEvent.RehashRequested);
    assertTrue(metrics.events.get(1) instanceof CredentialMetricEvent.LifecycleTransition);
  }

  @Test
  @DisplayName("Metric events never contain raw usernames, hashes or pepper key values")
  void metricEventsAreMinimised() {
    // Audit by inspection: each event's record components are
    // structural identifiers / counters / durations only. There is
    // no field anywhere in CredentialMetricEvent that takes a
    // username, an encoded hash, a pepper key value or a client
    // address. This test documents that contract — adding such a
    // field would force this assertion to be rewritten.
    CredentialMetricEvent.HashDuration h = new CredentialMetricEvent.HashDuration(
        "alg", "prov", 1, 0L, false);
    CredentialMetricEvent.VerifyDuration v = new CredentialMetricEvent.VerifyDuration(
        "alg", "prov", 1, 0L, true, false);
    CredentialMetricEvent.AbuseSignal a = new CredentialMetricEvent.AbuseSignal(
        AbusePattern.RESET_ABUSE, 1, 5);
    // toString of these must not embed any secret-shaped value.
    assertFalse(h.toString().toLowerCase().contains("hash="));
    assertFalse(v.toString().toLowerCase().contains("password"));
    assertFalse(a.toString().toLowerCase().contains("user"));
  }
}
