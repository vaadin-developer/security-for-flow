package com.svenruppert.jsentinel.monitoring.health;

/*-
 * #%L
 * jSentinel Monitoring — metrics, health and diagnostics export points
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

import com.svenruppert.jsentinel.audit.LoginSucceeded;
import com.svenruppert.jsentinel.audit.RingBufferAuditSink;
import com.svenruppert.jsentinel.dx.runtime.HealthFinding;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Saturation thresholds against a real {@link RingBufferAuditSink}
 * filled with real audit events — no doubles.
 */
class AuditStoreSaturationHealthIndicatorTest {

  private static RingBufferAuditSink filledSink(int capacity, int events) {
    RingBufferAuditSink sink = new RingBufferAuditSink(capacity);
    for (int i = 0; i < events; i++) {
      sink.accept(new LoginSucceeded(Instant.now(), "user-" + i, null, null));
    }
    return sink;
  }

  @Test
  @DisplayName("id() is the stable 'audit-store' identifier")
  void idIsStable() {
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(new RingBufferAuditSink(10));
    assertEquals("audit-store", indicator.id());
    assertEquals(AuditStoreSaturationHealthIndicator.ID, indicator.id());
  }

  @Test
  @DisplayName("below the warn ratio -> healthy (empty findings)")
  void belowThresholdIsHealthy() {
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 8), 0.9d);
    assertEquals(List.of(), indicator.check());
  }

  @Test
  @DisplayName("exactly at the warn ratio -> WARNING monitoring/audit-store-saturation")
  void atThresholdWarns() {
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 9), 0.9d);
    List<HealthFinding> findings = indicator.check();
    assertEquals(1, findings.size());
    HealthFinding finding = findings.get(0);
    assertEquals(Severity.WARNING, finding.severity());
    assertEquals(AuditStoreSaturationHealthIndicator.SATURATION_CODE, finding.code());
    assertTrue(finding.message().contains("9"),
        "message must carry the retained-event count: " + finding.message());
    assertTrue(finding.message().contains("10"),
        "message must carry the capacity: " + finding.message());
  }

  @Test
  @DisplayName("full ring buffer -> WARNING with the numbers in the message")
  void fullBufferWarns() {
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 10), 0.9d);
    List<HealthFinding> findings = indicator.check();
    assertEquals(1, findings.size());
    assertTrue(findings.get(0).message().contains("10 of 10"),
        "message must carry size and capacity: " + findings.get(0).message());
  }

  @Test
  @DisplayName("single-arg constructor defaults the warn ratio to 0.9")
  void singleArgConstructorUsesDefaultRatio() {
    assertEquals(0.9d, AuditStoreSaturationHealthIndicator.DEFAULT_WARN_RATIO);
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 9));
    assertEquals(1, indicator.check().size());
    AuditStoreSaturationHealthIndicator relaxed =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 8));
    assertEquals(List.of(), relaxed.check());
  }

  @Test
  @DisplayName("an emptied sink reports healthy again")
  void clearedSinkIsHealthyAgain() {
    RingBufferAuditSink sink = filledSink(10, 10);
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(sink);
    assertEquals(1, indicator.check().size());
    sink.clear();
    assertEquals(List.of(), indicator.check());
  }

  @Test
  @DisplayName("constructor guards: null sink and out-of-range warn ratios are rejected")
  void constructorGuards() {
    assertThrows(NullPointerException.class,
        () -> new AuditStoreSaturationHealthIndicator(null));
    RingBufferAuditSink sink = new RingBufferAuditSink(10);
    assertThrows(IllegalArgumentException.class,
        () -> new AuditStoreSaturationHealthIndicator(sink, 0.0d));
    assertThrows(IllegalArgumentException.class,
        () -> new AuditStoreSaturationHealthIndicator(sink, -0.5d));
    assertThrows(IllegalArgumentException.class,
        () -> new AuditStoreSaturationHealthIndicator(sink, 1.000001d));
    assertThrows(IllegalArgumentException.class,
        () -> new AuditStoreSaturationHealthIndicator(sink, Double.NaN));
  }

  @Test
  @DisplayName("warn ratio 1.0 is accepted and warns only when completely full")
  void warnRatioOfOneIsAccepted() {
    AuditStoreSaturationHealthIndicator indicator =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 9), 1.0d);
    assertEquals(List.of(), indicator.check());
    AuditStoreSaturationHealthIndicator full =
        new AuditStoreSaturationHealthIndicator(filledSink(10, 10), 1.0d);
    assertEquals(1, full.check().size());
  }
}
