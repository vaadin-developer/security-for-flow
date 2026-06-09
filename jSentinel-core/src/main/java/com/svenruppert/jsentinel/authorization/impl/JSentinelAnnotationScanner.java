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
package com.svenruppert.jsentinel.authorization.impl;

import com.svenruppert.jsentinel.authorization.annotations.JSentinelAnnotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Arrays.stream;

/**
 * Scans annotated elements for {@link JSentinelAnnotation}-meta-annotated
 * restriction annotations and resolves the corresponding evaluator class.
 * <p>
 * Results are cached per class. This class is Vaadin-free and can be
 * unit-tested independently.
 */
public final class JSentinelAnnotationScanner {

  /** Creates a new scanner with an empty cache. */
  public JSentinelAnnotationScanner() {
  }

  private final Map<AnnotatedElement, Optional<AnnotationAccessEvaluatorPair<Annotation>>> cache =
      new ConcurrentHashMap<>();

  /**
   * Scans the given class for a restriction annotation and returns the
   * annotation together with the evaluator class declared via
   * {@link JSentinelAnnotation}.
   *
   * @param navigationTarget the class to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Class<?> navigationTarget) {
    return scan((AnnotatedElement) navigationTarget);
  }

  /**
   * Scans the given method for a restriction annotation and returns the
   * annotation together with the evaluator class declared via
   * {@link JSentinelAnnotation}.
   *
   * @param method the method to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Method method) {
    return scan((AnnotatedElement) method);
  }

  /**
   * Scans the given annotated element for a restriction annotation and returns
   * the annotation together with the evaluator class declared via
   * {@link JSentinelAnnotation}.
   *
   * @param element the annotated element to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(AnnotatedElement element) {
    return cache.computeIfAbsent(element, this::doScan);
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> doScan(AnnotatedElement element) {
    List<Annotation> list = stream(element.getAnnotations())
        .filter(a -> a.annotationType().isAnnotationPresent(JSentinelAnnotation.class))
        .toList();

    return switch (list.size()) {
      case 0 -> Optional.empty();
      case 1 -> {
        Annotation annotation = list.getFirst();
        JSentinelAnnotation navAnno = annotation.annotationType()
            .getAnnotation(JSentinelAnnotation.class);
        Class<?> evaluatorClass = navAnno.value();
        var pair = new AnnotationAccessEvaluatorPair<>(annotation, evaluatorClass);
        yield Optional.of(pair);
      }
      default -> throw new IllegalStateException(
          "More than one @JSentinelAnnotation is not allowed on " + element);
    };
  }
}
