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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;

import java.lang.annotation.Annotation;

/**
 * Pairs a restriction annotation instance with the
 * evaluator class declared via
 * {@link eu.jsentinel.jcustos.authorization.annotations.JSentinelAnnotation}.
 *
 * @param annotation     the restriction annotation instance
 * @param evaluatorClass the evaluator class to instantiate
 * @param <T>            the annotation type
 */
public record AnnotationAccessEvaluatorPair<T extends Annotation>(
    T annotation,
    Class<?> evaluatorClass
) {

  /**
   * Compatibility accessor for Vaadin-oriented {@link AccessEvaluator}s.
   *
   * @return evaluator class cast to the legacy access evaluator type
   */
  @SuppressWarnings("unchecked")
  public Class<? extends AccessEvaluator<T>> accessEvaluatorClass() {
    return (Class<? extends AccessEvaluator<T>>) evaluatorClass;
  }
}
