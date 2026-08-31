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
package eu.jsentinel.jcustos.dx.runtime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("HealthFinding (V00.74.10 / Prompt 001)")
class HealthFindingTest {

  @Test
  void rejectsNullSeverity() {
    assertThrows(NullPointerException.class,
        () -> new HealthFinding(null, "test/code", "msg"));
  }

  @Test
  void rejectsNullCode() {
    assertThrows(NullPointerException.class,
        () -> new HealthFinding(Severity.INFO, null, "msg"));
  }

  @Test
  void rejectsNullMessage() {
    assertThrows(NullPointerException.class,
        () -> new HealthFinding(Severity.INFO, "test/code", null));
  }

  @Test
  void recordEqualityHonoursAllComponents() {
    HealthFinding a = new HealthFinding(Severity.WARNING, "x", "m");
    HealthFinding b = new HealthFinding(Severity.WARNING, "x", "m");
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }
}
