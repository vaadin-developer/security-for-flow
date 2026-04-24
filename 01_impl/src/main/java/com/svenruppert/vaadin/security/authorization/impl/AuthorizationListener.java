/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.annotations.NavigationAnnotation;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.server.*;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;

@ListenerPriority(Integer.MAX_VALUE - 1)
public class AuthorizationListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener, HasLogger, Serializable {

  @Serial
  private static final long serialVersionUID = 974589421761348380L;

  private final Map<Class<?>, Optional<AnnotationAccessEvaluatorPair<Annotation>>> cache = new ConcurrentHashMap<>();

  private final Predicate<Annotation> hasRestrictionAnnotation = annotation -> annotation.annotationType()
      .isAnnotationPresent(
          NavigationAnnotation.class);

  @Override
  public void uiInit(UIInitEvent event) {
    UI ui = event.getUI();
    Registration reg = ui.addBeforeEnterListener(this);
    ui.addDetachListener(e -> reg.remove());
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    event.getSource()
        .addUIInitListener(this);
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    checkAccessibility(event, event.getNavigationTarget());
  }

  private void checkAccessibility(BeforeEnterEvent event, Class<?> navigationTarget) {
    cache.computeIfAbsent(navigationTarget, this::accessEvaluatorPair)
        .ifPresent(accessEvaluatorPair -> {
          final Class<? extends AccessEvaluator<Annotation>> accessEvaluatorClass = accessEvaluatorPair.accessEvaluatorClass();
          requireNonNull(accessEvaluatorClass,
              "#checkAccess(BeforeEnterEvent) accessEvaluatorClass -> must not  null");

          final AccessEvaluator<Annotation> accessEvaluator = VaadinService.getCurrent()
              .getInstantiator()
              .getOrCreate(accessEvaluatorClass);

          requireNonNull(accessEvaluator, "#checkAccess(BeforeEnterEvent) accessEvaluatorClass ("
              + accessEvaluatorClass.getName()
              + ") -> could not instantiated");

          final Location location = event.getLocation();
          final Annotation anno = accessEvaluatorPair.annotation();
          logger().info("evaluate access for location : {} and annotation {}", location, anno);
          final Access evaluate = accessEvaluator.evaluate(location, navigationTarget, anno);

          final Access access = requireNonNull(evaluate, () -> accessEvaluatorClass
              + "#checkAccess(BeforeEnterEvent) accessEvaluator.evaluate -> must not return null");

          access.exec(event);
        });
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> accessEvaluatorPair(Class<?> classToCheck) {

    List<Annotation> list = stream(classToCheck.getAnnotations())
        .filter(hasRestrictionAnnotation)
        .toList();

    return switch (list.size()) {
      case 0 -> Optional.empty();
      case 1 -> {
        final Annotation annotation = list.getFirst();
        Class<? extends Annotation> aClass = annotation.annotationType();
        NavigationAnnotation navigationAnnotation = aClass.getAnnotation(NavigationAnnotation.class);
        Class<? extends AccessEvaluator<? extends Annotation>> accessEvaluator = navigationAnnotation.value();
        @SuppressWarnings("unchecked")
        final AnnotationAccessEvaluatorPair<Annotation> value = new AnnotationAccessEvaluatorPair<>(
            annotation, (Class<? extends AccessEvaluator<Annotation>>) accessEvaluator);
        yield Optional.of(value);
      }
      default -> throw new IllegalStateException("more than one NavigationAnnotation not allowed at " + classToCheck);
    };
  }

}
