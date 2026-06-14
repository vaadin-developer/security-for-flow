/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.dx.runtime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("HealthStatus (V00.74.10 / Prompt 002)")
class HealthStatusTest {

  private static final Instant T0 = Instant.parse("2026-06-14T09:00:00Z");

  @Test
  void rejectsNullOverall() {
    assertThrows(NullPointerException.class,
        () -> new HealthStatus(null, List.of(), 0, T0));
  }

  @Test
  void rejectsNullFindings() {
    assertThrows(NullPointerException.class,
        () -> new HealthStatus(Health.HEALTHY, null, 0, T0));
  }

  @Test
  void rejectsNullInspectedAt() {
    assertThrows(NullPointerException.class,
        () -> new HealthStatus(Health.HEALTHY, List.of(), 0, null));
  }

  @Test
  void rejectsNegativeRegisteredServices() {
    assertThrows(IllegalArgumentException.class,
        () -> new HealthStatus(Health.HEALTHY, List.of(), -1, T0));
  }

  @Test
  void findingsListIsDefensivelyCopied() {
    List<HealthFinding> input = new ArrayList<>();
    input.add(new HealthFinding(Severity.WARNING, "x", "m"));
    HealthStatus s = new HealthStatus(Health.DEGRADED, input, 1, T0);
    input.add(new HealthFinding(Severity.ERROR, "y", "n"));
    assertEquals(1, s.findings().size(),
        "post-construction mutation must not leak into the record");
    assertThrows(UnsupportedOperationException.class,
        () -> s.findings().add(new HealthFinding(Severity.INFO, "z", "o")));
  }

  @Test
  void findingsBySeverityFilters() {
    HealthStatus s = new HealthStatus(
        Health.DEGRADED,
        List.of(
            new HealthFinding(Severity.INFO, "a", "1"),
            new HealthFinding(Severity.WARNING, "b", "2"),
            new HealthFinding(Severity.INFO, "c", "3")),
        2, T0);
    assertEquals(2, s.findingsBySeverity(Severity.INFO).size());
    assertEquals(1, s.findingsBySeverity(Severity.WARNING).size());
    assertEquals(0, s.findingsBySeverity(Severity.ERROR).size());
  }

  @Test
  void hasErrorsAndIsDegradedReflectOverall() {
    HealthStatus healthy = new HealthStatus(Health.HEALTHY, List.of(), 0, T0);
    HealthStatus degraded = new HealthStatus(Health.DEGRADED, List.of(), 0, T0);
    HealthStatus failed = new HealthStatus(Health.FAILED, List.of(), 0, T0);

    assertFalse(healthy.hasErrors());
    assertFalse(healthy.isDegraded());

    assertFalse(degraded.hasErrors());
    assertTrue(degraded.isDegraded());

    assertTrue(failed.hasErrors());
    assertFalse(failed.isDegraded());
  }

  @Test
  void findingsBySeverityRejectsNull() {
    HealthStatus s = new HealthStatus(Health.HEALTHY, List.of(), 0, T0);
    assertThrows(NullPointerException.class, () -> s.findingsBySeverity(null));
  }
}
