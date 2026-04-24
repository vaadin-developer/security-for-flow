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

import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Arrays.stream;

/**
 * Scans navigation target classes for {@link NavigationAnnotation}-meta-annotated
 * restriction annotations and resolves the corresponding {@link AccessEvaluator}.
 * <p>
 * Results are cached per class. This class is Vaadin-free and can be
 * unit-tested independently.
 */
public final class NavigationAnnotationScanner {

  /** Creates a new scanner with an empty cache. */
  public NavigationAnnotationScanner() {
  }

  private final Map<Class<?>, Optional<AnnotationAccessEvaluatorPair<Annotation>>> cache =
      new ConcurrentHashMap<>();

  /**
   * Scans the given class for a restriction annotation and returns the
   * annotation together with the evaluator class declared via
   * {@link NavigationAnnotation}.
   *
   * @param navigationTarget the class to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Class<?> navigationTarget) {
    return cache.computeIfAbsent(navigationTarget, this::doScan);
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> doScan(Class<?> classToCheck) {
    List<Annotation> list = stream(classToCheck.getAnnotations())
        .filter(a -> a.annotationType().isAnnotationPresent(NavigationAnnotation.class))
        .toList();

    return switch (list.size()) {
      case 0 -> Optional.empty();
      case 1 -> {
        Annotation annotation = list.getFirst();
        NavigationAnnotation navAnno = annotation.annotationType()
            .getAnnotation(NavigationAnnotation.class);
        Class<? extends AccessEvaluator<? extends Annotation>> evaluatorClass = navAnno.value();
        @SuppressWarnings("unchecked")
        var pair = new AnnotationAccessEvaluatorPair<>(
            annotation, (Class<? extends AccessEvaluator<Annotation>>) evaluatorClass);
        yield Optional.of(pair);
      }
      default -> throw new IllegalStateException(
          "More than one @NavigationAnnotation is not allowed on " + classToCheck.getName());
    };
  }
}
