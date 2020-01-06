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
package org.rapidpm.vaadin.security.authorization.api;

import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.Location;
import org.rapidpm.vaadin.security.authorization.annotations.NavigationAnnotation;
import org.rapidpm.vaadin.security.authorization.impl.Access;

import java.lang.annotation.Annotation;

public interface AccessEvaluator<T extends Annotation> {

  /**
   * evaluate what access the current user has to the route-target in question.
   *
   * @param location         the {@link Location} to be navigated to, see {@link
   *                         BeforeEnterEvent#getLocation()}
   * @param navigationTarget the navigation-target to be navigated to, see {@link
   *                         BeforeEnterEvent#getNavigationTarget()}
   * @param annotation       the {@link Annotation} on the route-target that itself is annotated
   *                         with a {@link NavigationAnnotation}. This annotation may carry
   *                         additional data which can be used to evaluate the access.
   * @return the {@link Access}
   */
  Access evaluate(Location location, Class<?> navigationTarget, T annotation);
}