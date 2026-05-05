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
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.vaadin.security.authorization.annotations.ProtectedBy;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;

/**
 * Evaluates {@link ProtectedBy} by delegating to the evaluator declared on the
 * annotation instance.
 */
public final class ProtectedByEvaluator implements AuthorizationEvaluator<ProtectedBy> {

  @Override
  public AuthorizationDecision evaluate(AccessContext context, ProtectedBy annotation) {
    AuthorizationEvaluator<ProtectedBy> evaluator = instantiate(annotation.value());
    return evaluator.evaluate(context, annotation);
  }

  private static AuthorizationEvaluator<ProtectedBy> instantiate(
      Class<? extends AuthorizationEvaluator<ProtectedBy>> evaluatorClass) {
    try {
      return evaluatorClass.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "Could not instantiate authorization evaluator " + evaluatorClass.getName(), e);
    }
  }
}
