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