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

import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.server.*;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.security.authorization.annotations.NavigationAnnotation;
import org.rapidpm.vaadin.security.authorization.api.AccessEvaluator;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;

@ListenerPriority(Integer.MAX_VALUE - 1)
public class AuthorizationListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener, HasLogger, Serializable {

  private static final long serialVersionUID = 974589421761348380L;

  private final Map<Class<?>, Optional<AnnotationAccessEvaluatorPair<Annotation>>> cache = new ConcurrentHashMap<>();

  private final Predicate<Annotation> hasRestrictionAnnotation = annotation -> annotation.annotationType()
                                                                                         .isAnnotationPresent(
                                                                                             NavigationAnnotation.class);

  @Override
  public void uiInit(UIInitEvent event) {
    event.getUI()
         .addBeforeEnterListener(this);
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

  @SuppressWarnings("unchecked")
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

           final Location   location = event.getLocation();
           final Annotation anno     = accessEvaluatorPair.annotation();
           logger().info("evaluate access for location : " + location + " and annotation " + anno);
           final Access evaluate = accessEvaluator.evaluate(location, navigationTarget, anno);

           final Access access = requireNonNull(evaluate, () -> accessEvaluatorClass
                                                                + "#checkAccess(BeforeEnterEvent) accessEvaluator.evaluate -> must not return null");

           access.exec(event);
         });
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> accessEvaluatorPair(Class<?> classToCheck) {

    List<Annotation> list = stream(classToCheck.getAnnotations()).filter(hasRestrictionAnnotation)
                                                                 .collect(toList());

    switch (list.size()) {
      case 0:
        return Optional.empty();
      case 1:
        final Annotation annotation = list.get(0);
        Class<? extends Annotation> aClass = annotation.annotationType();
        NavigationAnnotation navigationAnnotation = aClass.getAnnotation(NavigationAnnotation.class);
        Class<? extends AccessEvaluator<? extends Annotation>> accessEvaluator = navigationAnnotation.value();
        final AnnotationAccessEvaluatorPair value = new AnnotationAccessEvaluatorPair(annotation, accessEvaluator);
        return Optional.of(value);
      default:
        throw new IllegalStateException("more than one NavigationAnnotation not allowed at " + classToCheck);
    }
  }

}
