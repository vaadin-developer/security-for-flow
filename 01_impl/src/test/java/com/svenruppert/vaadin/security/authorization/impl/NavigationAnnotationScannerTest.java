/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.vaadin.security.authorization.annotations.NavigationAnnotation;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.vaadin.flow.router.Location;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("NavigationAnnotationScanner")
class NavigationAnnotationScannerTest {

  private NavigationAnnotationScanner scanner;

  @BeforeEach
  void setUp() {
    scanner = new NavigationAnnotationScanner();
  }

  @Test
  @DisplayName("class without restriction annotation returns empty")
  void noAnnotation_returnsEmpty() {
    var result = scanner.scan(PlainView.class);
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("class with restriction annotation returns pair")
  void withAnnotation_returnsPair() {
    var result = scanner.scan(ProtectedView.class);
    assertTrue(result.isPresent());
    var pair = result.get();
    assertEquals(StubEvaluator.class, pair.accessEvaluatorClass());
    assertInstanceOf(StubRestriction.class, pair.annotation());
  }

  @Test
  @DisplayName("result is cached across calls")
  void resultIsCached() {
    var first = scanner.scan(ProtectedView.class);
    var second = scanner.scan(ProtectedView.class);
    assertSame(first, second);
  }

  @Test
  @DisplayName("multiple restriction annotations throws IllegalStateException")
  void multipleAnnotations_throws() {
    assertThrows(IllegalStateException.class,
        () -> scanner.scan(DualAnnotatedView.class));
  }

  // ── Test fixtures ─────────────────────────────────────────────

  @Retention(RetentionPolicy.RUNTIME)
  @NavigationAnnotation(StubEvaluator.class)
  @interface StubRestriction {
  }

  @Retention(RetentionPolicy.RUNTIME)
  @NavigationAnnotation(StubEvaluator.class)
  @interface AnotherRestriction {
  }

  static class StubEvaluator implements AccessEvaluator<Annotation> {
    @Override
    public Access evaluate(Location location, Class<?> navigationTarget, Annotation annotation) {
      return Access.granted();
    }
  }

  static class PlainView {
  }

  @StubRestriction
  static class ProtectedView {
  }

  @StubRestriction
  @AnotherRestriction
  static class DualAnnotatedView {
  }
}
