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

import com.svenruppert.vaadin.security.authorization.annotations.JSentinelAnnotation;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.authorization.navigation.AccessDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JSentinelAnnotationScanner")
class JSentinelAnnotationScannerTest {

  private JSentinelAnnotationScanner scanner;

  @BeforeEach
  void setUp() {
    scanner = new JSentinelAnnotationScanner();
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
    assertEquals(StubEvaluator.class, pair.evaluatorClass());
    assertInstanceOf(StubRestriction.class, pair.annotation());
  }

  @Test
  @DisplayName("method with restriction annotation returns pair")
  void methodWithAnnotation_returnsPair() throws NoSuchMethodException {
    Method method = ProtectedHandler.class.getDeclaredMethod("delete");

    var result = scanner.scan(method);

    assertTrue(result.isPresent());
    assertEquals(StubEvaluator.class, result.get().evaluatorClass());
    assertInstanceOf(StubRestriction.class, result.get().annotation());
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

  @Test
  @DisplayName("non-security annotations alongside the restriction are filtered out")
  void filtersNonJSentinelAnnotations() {
    var result = scanner.scan(MixedAnnotatedView.class);
    assertTrue(result.isPresent(),
        "@Deprecated alongside @StubRestriction must not bump the security count past 1");
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  // ── Test fixtures ─────────────────────────────────────────────

  @Retention(RetentionPolicy.RUNTIME)
  @JSentinelAnnotation(StubEvaluator.class)
  @interface StubRestriction {
  }

  @Retention(RetentionPolicy.RUNTIME)
  @JSentinelAnnotation(StubEvaluator.class)
  @interface AnotherRestriction {
  }

  static class StubEvaluator implements AccessEvaluator<Annotation> {
    @Override
    public AccessDecision evaluate(AccessContext context, Annotation annotation) {
      return AccessDecision.granted();
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

  @SuppressWarnings("DeprecatedIsStillUsed")
  @StubRestriction
  @Deprecated
  static class MixedAnnotatedView {
  }

  static class ProtectedHandler {
    @StubRestriction
    void delete() {
    }
  }
}
