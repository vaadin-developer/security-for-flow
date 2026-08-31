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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.authorization.annotations.JSentinelAnnotation;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;

import java.lang.annotation.Annotation;

/**
 * Evaluates whether the current subject has access to a route target.
 * <p>
 * Implementations are linked to restriction annotations via
 * {@link JSentinelAnnotation}. The framework calls
 * {@link #evaluate(AccessContext, Annotation)} to obtain a
 * Vaadin-free {@link AccessDecision}.
 *
 * @param <T> the restriction annotation type
 */
public interface AccessEvaluator<T extends Annotation> {

  /**
   * Evaluate access and return a Vaadin-free decision.
   *
   * @param context          the adapter-neutral access context
   * @param annotation       the {@link Annotation} on the route-target that itself is annotated
   *                         with a {@link JSentinelAnnotation}. This annotation may carry
   *                         additional data which can be used to evaluate the access.
   * @return the {@link AccessDecision}
   */
  AccessDecision evaluate(AccessContext context, T annotation);
}
