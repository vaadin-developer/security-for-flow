/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rapidpm.vaadin.security.authorization.impl;

import org.rapidpm.frp.model.Pair;
import org.rapidpm.vaadin.security.authorization.api.AccessEvaluator;

import java.lang.annotation.Annotation;

public class AnnotationAccessEvaluatorPair<T extends Annotation>
    extends Pair<T, Class<? extends AccessEvaluator<T>>> {

  public AnnotationAccessEvaluatorPair(T t, Class<? extends AccessEvaluator<T>> aClass) {
    super(t, aClass);
  }

  public T annotation() {
    return getT1();
  }

  public Class<? extends AccessEvaluator<T>> accessEvaluatorClass() {
    return getT2();
  }
}
