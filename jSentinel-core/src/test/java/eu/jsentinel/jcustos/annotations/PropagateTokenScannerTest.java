/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.annotations;

import eu.jsentinel.jcustos.authorization.impl.JSentinelAnnotationScanner;
import eu.jsentinel.jcustos.credential.propagation.PropagateTokenAdvisor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("@PropagateToken — scanner integration")
class PropagateTokenScannerTest {

  private final JSentinelAnnotationScanner scanner = new JSentinelAnnotationScanner();

  @Test
  @DisplayName("Class-level @PropagateToken is discovered at the class level")
  void classLevelFound() {
    var pair = scanner.scan(ClassLevelClient.class).orElseThrow();
    assertTrue(pair.annotation() instanceof PropagateToken);
    assertSame(PropagateTokenAdvisor.class, pair.evaluatorClass());
    assertEquals("pass-through",
        ((PropagateToken) pair.annotation()).strategy());
  }

  @Test
  @DisplayName("Method-level @PropagateToken is discovered at the method level")
  void methodLevelFound() throws NoSuchMethodException {
    Method method = MethodLevelClient.class.getMethod("archive", String.class);
    var pair = scanner.scan(method).orElseThrow();
    PropagateToken ann = (PropagateToken) pair.annotation();
    assertEquals("exchange", ann.strategy());
    assertEquals("api.example.com", ann.audience());
  }

  @Test
  @DisplayName("Class without @PropagateToken returns empty")
  void notAnnotated() {
    assertTrue(scanner.scan(NotAnnotated.class).isEmpty());
  }

  @Test
  @DisplayName("Method-level annotation does not bleed onto sibling methods")
  void methodLevelLocal() throws NoSuchMethodException {
    Method load = MethodLevelClient.class.getMethod("load", String.class);
    assertTrue(scanner.scan(load).isEmpty(),
        "load() has no method-level annotation; class is not annotated, so scan must be empty");
  }

  @PropagateToken
  interface ClassLevelClient {
    String load(String id);
  }

  interface MethodLevelClient {
    String load(String id);

    @PropagateToken(strategy = "exchange", audience = "api.example.com")
    void archive(String id);
  }

  interface NotAnnotated {
    String load(String id);
  }
}
